"""Local-mode failure handling of the composite Action (scripts/action/*.sh).

The scan step records whether a report exists; the gate decides the job from
the scan's exit code alone and fails closed on anything it cannot read. Both
scripts run here as subprocesses, the way action.yml runs them, with a stub
`fendix` on PATH so no network or engine is needed.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

import yaml

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts" / "action"
SPACED_REPORT = "reports dir/fendix results.sarif"


def outputs(path):
    """$GITHUB_OUTPUT as the runner reads it: a later write of a name wins."""
    values = {}
    for line in Path(path).read_text().splitlines():
        name, _, value = line.partition("=")
        values[name] = value
    return values


class EnforceTests(unittest.TestCase):
    def enforce(self, exit_code, **overrides):
        env = {
            "PATH": os.environ["PATH"],
            "EXIT_CODE": exit_code,
            "FAIL_ON": "CRITICAL",
            "REPORT": SPACED_REPORT,
            "REPORT_PRESENT": "true",
            "SARIF_UPLOAD": "skipped",
        }
        env.update(overrides)
        return subprocess.run(["bash", str(SCRIPTS / "enforce.sh")], env=env, capture_output=True, text=True)

    def assertNoShellError(self, result):
        for noise in ("numeric argument required", "syntax error", "command not found", "unbound variable"):
            self.assertNotIn(noise, result.stdout + result.stderr)

    def test_empty_code_is_a_setup_failure(self):
        result = self.enforce("", REPORT_PRESENT="")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Fendix did not run", result.stdout)
        self.assertIn("setup step failed before the scan", result.stdout)
        self.assertNoShellError(result)

    def test_zero_passes(self):
        result = self.enforce("0", COVERAGE="complete", REQUIRED="semgrep", REQUIRED_RESULT="satisfied")
        self.assertEqual(result.returncode, 0)
        self.assertIn("✓ Fendix: no finding reached BLOCK", result.stdout)
        self.assertIn("Required analyzers: semgrep. Coverage: complete.", result.stdout)
        self.assertIn(SPACED_REPORT, result.stdout)
        self.assertNotIn("::error", result.stdout)
        self.assertNotIn("::warning", result.stdout)

    def test_zero_with_incomplete_coverage_is_a_warning_not_a_clean_scan(self):
        result = self.enforce("0", COVERAGE="incomplete (govulncheck)", REQUIRED="semgrep")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("::warning title=Fendix coverage incomplete::"), result.stdout)
        self.assertIn("incomplete (govulncheck)", result.stdout)
        self.assertNotIn("✓", result.stdout)

    def test_zero_without_a_coverage_verdict_is_a_warning(self):
        result = self.enforce("0", COVERAGE="")
        self.assertEqual(result.returncode, 0)
        self.assertIn("::warning title=Fendix coverage incomplete::", result.stdout)
        self.assertIn("not reported by the engine", result.stdout)
        self.assertNotIn("✓", result.stdout)

    def test_opt_out_warns_that_coverage_is_not_enforced(self):
        for complete in ("complete", "incomplete (semgrep)"):
            with self.subTest(coverage=complete):
                result = self.enforce("0", REQUIRE_INPUT="none", REQUIRED="", COVERAGE=complete)
                self.assertEqual(result.returncode, 0)
                self.assertTrue(result.stdout.startswith("::warning title=Fendix coverage not enforced::"), result.stdout)
                self.assertIn("require-analyzers is none", result.stdout)
                self.assertIn(complete, result.stdout)
                self.assertNotIn("✓", result.stdout)

    def test_required_analyzer_not_delivered_names_it(self):
        result = self.enforce("2", REQUIRED="semgrep", REQUIRED_RESULT="not delivered (semgrep)",
                              REQUIRED_DETAIL="semgrep: failed (execution_error)", COVERAGE="incomplete (semgrep)")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stdout.startswith("::error title=Fendix required analyzer semgrep was not delivered::"), result.stdout)
        self.assertIn("semgrep: failed (execution_error)", result.stdout)
        self.assertIn("partial report was not uploaded", result.stdout)
        self.assertNotIn("no finding reached BLOCK", result.stdout)
        result = self.enforce("2", REQUIRED="semgrep,secrets", REQUIRED_RESULT="not delivered (semgrep, secrets)",
                              REQUIRED_DETAIL="semgrep: unavailable (dependency_missing); secrets: failed (input_error)")
        self.assertIn("title=Fendix required analyzer semgrep%2C secrets was not delivered::", result.stdout)

    def test_failures_never_print_the_clean_line(self):
        for code in ("", "1", "2", "3", "abc"):
            with self.subTest(code=code):
                result = self.enforce(code, COVERAGE="complete")
                self.assertNotIn("no finding reached BLOCK", result.stdout)
                self.assertNotIn("✓", result.stdout)

    def summary(self, exit_code, **overrides):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "summary.md"
            self.enforce(exit_code, GITHUB_STEP_SUMMARY=str(path), **overrides)
            return path.read_text()

    def test_step_summary_states_the_result_and_the_requirement(self):
        text = self.summary("0", COVERAGE="complete", REQUIRED="semgrep", REQUIRED_RESULT="satisfied")
        self.assertIn("| Result | Passed: no finding reached BLOCK status |", text)
        self.assertIn("| Required analyzers | semgrep (satisfied) |", text)
        self.assertIn("| Coverage | complete |", text)
        text = self.summary("0", REQUIRE_INPUT="none", REQUIRED="", COVERAGE="incomplete (semgrep)")
        self.assertIn("**Not enforced**", text)
        self.assertIn("coverage is not enforced", text)
        self.assertNotIn("Passed", text)
        text = self.summary("", REPORT_PRESENT="")
        self.assertIn("Did not run", text)
        self.assertNotIn("Passed", text)

    def test_step_summary_escapes_table_cells(self):
        text = self.summary("1", REPORT="a|b<script>.sarif", COVERAGE="complete")
        self.assertIn("a\\|b&lt;script&gt;.sarif", text)
        self.assertNotIn("<script>", text)

    def test_one_is_a_policy_block_at_the_configured_threshold(self):
        result = self.enforce("1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCK", result.stdout)
        self.assertIn("CRITICAL", result.stdout)
        self.assertNotIn("HIGH", result.stdout)
        self.assertIn("scan log", result.stdout)
        self.assertIn(SPACED_REPORT, result.stdout)

    def test_two_is_a_scan_error(self):
        result = self.enforce("2", REPORT_PRESENT="false")
        self.assertEqual(result.returncode, 2)
        self.assertIn("did not complete", result.stdout)
        self.assertIn("No report was written", result.stdout)
        self.assertNoShellError(result)

    def test_unknown_numeric_code_fails_closed(self):
        for code in ("3", "125", "137", "-1", "01"):
            with self.subTest(code=code):
                result = self.enforce(code)
                self.assertEqual(result.returncode, 2)
                self.assertIn("failing closed", result.stdout)
                self.assertNoShellError(result)

    def test_non_numeric_code_fails_closed(self):
        for code in ("abc", " 0", "0 ", "1.0", "0;echo pwned", "$(echo pwned)", "0\n::warning::x"):
            with self.subTest(code=code):
                result = self.enforce(code)
                self.assertEqual(result.returncode, 2)
                self.assertIn("failing closed", result.stdout)
                self.assertNotIn("pwned\n", result.stdout)
                self.assertNoShellError(result)
                self.assertFalse(any(line.startswith("::warning") for line in result.stdout.splitlines()))

    def test_code_scanning_is_mentioned_only_after_a_successful_upload(self):
        self.assertIn("code scanning", self.enforce("1", SARIF_UPLOAD="success").stdout)
        for outcome in ("skipped", "failure", "cancelled", ""):
            with self.subTest(outcome=outcome):
                result = self.enforce("1", SARIF_UPLOAD=outcome)
                self.assertNotIn("code scanning", result.stdout)
                self.assertNotIn("Security tab", result.stdout)

    def test_report_path_cannot_inject_a_workflow_command(self):
        result = self.enforce("1", REPORT="x\n::warning::injected")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(any(line.startswith("::warning") for line in result.stdout.splitlines()))


class ScanTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.work = self.root / "work"
        (self.work / "reports dir").mkdir(parents=True)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "fendix"
        # Records its argv and the outputs present when it ran, then writes
        # (or not) the --output file and exits with $FAKE_EXIT.
        stub.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            printf '%s\\n' "$@" > "$FAKE_DIR/argv"
            cp "$GITHUB_OUTPUT" "$FAKE_DIR/outputs-at-scan"
            [ -n "${FAKE_STDERR:-}" ] && printf '%b' "$FAKE_STDERR" >&2
            out=""; prev=""
            for arg in "$@"; do [ "$prev" = "--output" ] && out="$arg"; prev="$arg"; done
            case "$FAKE_REPORT" in
              write) printf '{"version":"2.1.0","runs":[]}' > "$out" ;;
              empty) : > "$out" ;;
            esac
            exit "$FAKE_EXIT"
        """))
        stub.chmod(0o755)
        self.path = f"{bin_dir}:{os.environ['PATH']}"
        self.github_output = self.root / "github_output"

    def scan(self, *, fake_exit=0, fake_report="write", output=SPACED_REPORT, required="", extra_args="", stderr=""):
        self.github_output.write_text("")
        env = {
            "PATH": self.path,
            "GITHUB_OUTPUT": str(self.github_output),
            "RUNNER_TEMP": str(self.root),
            "FAKE_DIR": str(self.root),
            "FAKE_EXIT": str(fake_exit),
            "FAKE_REPORT": fake_report,
            "FAKE_STDERR": stderr,
            "CODE": ".", "URL": "", "SPEC": "", "FAIL_ON": "HIGH", "FORMAT": "sarif",
            "OUTPUT": output, "DIFF": "false", "EXTRA_ARGS": extra_args, "REQUIRED": required,
        }
        result = subprocess.run(["bash", str(SCRIPTS / "scan.sh")], cwd=self.work, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return outputs(self.github_output)

    def test_report_presence_is_false_before_the_scan_runs(self):
        self.scan()
        self.assertEqual(outputs(self.root / "outputs-at-scan").get("report-present"), "false")

    def test_present_non_empty_report_with_spaces_in_its_path(self):
        out = self.scan(fake_exit=1)
        self.assertEqual(out["report-present"], "true")
        self.assertEqual(out["exit-code"], "1")
        self.assertEqual(out["report"], SPACED_REPORT)
        self.assertIn(SPACED_REPORT, (self.root / "argv").read_text().splitlines())

    def argv(self):
        return (self.root / "argv").read_text().splitlines()

    def test_required_analyzers_reach_the_engine_before_extra_args(self):
        self.scan(required="semgrep", extra_args="--require-analyzers= --fast")
        argv = self.argv()
        self.assertEqual(argv[argv.index("--require-analyzers") + 1], "semgrep")
        self.assertLess(argv.index("--require-analyzers"), argv.index("--require-analyzers="))
        self.assertLess(argv.index("--require-analyzers"), argv.index("--fast"))

    def test_no_requirement_passes_no_flag(self):
        self.scan(required="")
        self.assertNotIn("--require-analyzers", self.argv())

    def test_malformed_requirement_fails_closed_without_scanning(self):
        for value in ("semgrep;id", "semgrep secrets", "Semgrep", "semgrep,", "-x"):
            with self.subTest(value=value):
                (self.root / "argv").unlink(missing_ok=True)
                out = self.scan(required=value)
                self.assertEqual(out["exit-code"], "2")
                self.assertFalse((self.root / "argv").exists())

    def test_engine_coverage_verdict_is_recorded_last_line_wins(self):
        out = self.scan(fake_exit=2, stderr=(
            "coverage: complete\\n"
            "\\nCoverage:\\n  analyzer  class\\n  semgrep  failed\\n"
            "coverage: incomplete (semgrep)\\nrequired: not delivered (semgrep)\\n"
            "fendix: required analyzer(s) not delivered: semgrep: failed (execution_error)\\n"), required="semgrep")
        self.assertEqual(out["coverage"], "incomplete (semgrep)")
        self.assertEqual(out["required-result"], "not delivered (semgrep)")
        self.assertEqual(out["required-detail"], "semgrep: failed (execution_error)")

    def test_no_verdict_leaves_the_outputs_empty(self):
        out = self.scan()
        self.assertEqual((out["coverage"], out["required-result"], out["required-detail"]), ("", "", ""))

    def test_a_failed_scans_partial_report_is_written_but_not_for_upload(self):
        out = self.scan(fake_exit=2, fake_report="write")
        self.assertEqual(out["report-written"], "true")
        self.assertEqual(out["report-present"], "false")
        for code in (0, 1):
            with self.subTest(code=code):
                out = self.scan(fake_exit=code)
                self.assertEqual((out["report-written"], out["report-present"]), ("true", "true"))

    def test_missing_report(self):
        out = self.scan(fake_exit=2, fake_report="none")
        self.assertEqual(out["report-present"], "false")
        self.assertEqual(out["exit-code"], "2")

    def test_empty_report_is_not_present(self):
        out = self.scan(fake_exit=0, fake_report="empty")
        self.assertEqual(out["report-present"], "false")

    def test_a_stale_report_from_before_the_scan_is_not_reused(self):
        (self.work / SPACED_REPORT).write_text('{"stale": true}')
        out = self.scan(fake_exit=2, fake_report="none")
        self.assertEqual(out["report-present"], "false")

    def test_records_every_exit_code(self):
        for code in (0, 1, 2):
            with self.subTest(code=code):
                self.assertEqual(self.scan(fake_exit=code)["exit-code"], str(code))

    def test_multiline_output_path_fails_closed_without_running_the_scan(self):
        out = self.scan(output="report.sarif\nexit-code=0")
        self.assertEqual(out["exit-code"], "2")
        self.assertEqual(out["report-present"], "false")
        self.assertFalse((self.root / "argv").exists())


class ActionWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        action = yaml.safe_load((REPO / "action.yml").read_text())
        cls.steps = {step.get("name"): step for step in action["runs"]["steps"]}

    def test_upload_requires_a_present_report(self):
        self.assertIn("steps.scan.outputs.report-present == 'true'", self.steps["Upload SARIF to code scanning"]["if"])

    def test_require_analyzers_input_defaults_to_auto(self):
        action = yaml.safe_load((REPO / "action.yml").read_text())
        self.assertEqual(action["inputs"]["require-analyzers"]["default"], "auto")

    def test_preflight_runs_after_preparation_and_before_the_scan(self):
        names = list(self.steps)
        prepare, preflight, scan = (names.index(n) for n in ("Prepare Fendix Python engine", "Preflight required analyzers", "Run Fendix scan"))
        self.assertLess(prepare, preflight)
        self.assertLess(preflight, scan)
        step = self.steps["Preflight required analyzers"]
        self.assertNotIn("if", step)  # managed mode too, and never after a failed step
        self.assertEqual(step["run"].strip(), '"$PYTHON" "$ACTION_PATH/scripts/action/analyzer_preflight.py"')
        self.assertEqual(step["env"]["REQUIRED"], "${{ steps.prepare.outputs.required-analyzers }}")

    def test_the_resolved_requirement_reaches_the_scan_and_the_gate(self):
        prepare = self.steps["Prepare Fendix Python engine"]
        self.assertEqual(prepare["id"], "prepare")
        self.assertEqual(prepare["env"]["REQUIRE_ANALYZERS"], "${{ inputs.require-analyzers }}")
        for name in ("Run Fendix scan", "Enforce fail-on threshold"):
            self.assertEqual(self.steps[name]["env"]["REQUIRED"], "${{ steps.prepare.outputs.required-analyzers }}")
        gate = self.steps["Enforce fail-on threshold"]["env"]
        self.assertEqual(gate["REPORT_PRESENT"], "${{ steps.scan.outputs.report-written }}")
        self.assertEqual(gate["REQUIRE_INPUT"], "${{ inputs.require-analyzers }}")

    def test_managed_mode_refuses_a_narrowed_requirement(self):
        step = self.steps["Validate managed inputs"]
        self.assertEqual(step["env"]["REQUIRE_ANALYZERS"], "${{ inputs.require-analyzers }}")
        self.assertIn('[ "$REQUIRE_ANALYZERS" = auto ] || fail', step["run"])

    def test_local_scan_and_gate_run_the_scripts_without_interpolating_inputs(self):
        for name, script in (("Run Fendix scan", "scan.sh"), ("Enforce fail-on threshold", "enforce.sh")):
            with self.subTest(step=name):
                step = self.steps[name]
                self.assertEqual(step["run"].strip(), f'bash "$ACTION_PATH/scripts/action/{script}"')
                self.assertEqual(step["env"]["ACTION_PATH"], "${{ github.action_path }}")
                self.assertNotIn("${{", step["run"])


if __name__ == "__main__":
    unittest.main()
