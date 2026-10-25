#!/usr/bin/env bash
# Local-mode gate of the composite Action (action.yml "Enforce fail-on
# threshold"). The scan's exit code alone decides the job: reporting steps
# never do, and a value this script cannot read fails closed. What it prints
# never reads as a clean scan unless the scan ran, its required analyzers
# were delivered and its coverage was complete.
#
#   EXIT_CODE        steps.scan.outputs.exit-code, empty when the scan never ran
#   FAIL_ON          the fail-on input, named in the BLOCK message
#   REPORT           the output input
#   REPORT_PRESENT   steps.scan.outputs.report-written: a report exists,
#                    complete or (after exit 2) partial
#   SARIF_UPLOAD     outcome of the SARIF upload step (success, failure, skipped)
#   REQUIRE_INPUT    the require-analyzers input (auto, none or a list)
#   REQUIRED         the analyzers preparation resolved it to (comma-separated)
#   COVERAGE         steps.scan.outputs.coverage: complete | incomplete (...)
#   REQUIRED_RESULT  steps.scan.outputs.required-result
#   REQUIRED_DETAIL  steps.scan.outputs.required-detail
#
# Writes a short result table to $GITHUB_STEP_SUMMARY when it is set.
set -u
# Bash 5.2 reads & in a ${var//pattern/replacement} as the matched text;
# cell() needs it literal. Older bash has no such option.
shopt -u patsub_replacement 2>/dev/null || true

# Escape a value for a workflow-command line, so it can never end the line
# and start a command of its own.
esc() {
  local s=${1//%/%25}
  s=${s//$'\r'/%0D}
  printf '%s' "${s//$'\n'/%0A}"
}

# A value for one Markdown table cell.
cell() {
  local s=${1//$'\r'/ }
  s=${s//$'\n'/ }
  s=${s//&/&amp;}
  s=${s//</&lt;}
  s=${s//>/&gt;}
  printf '%s' "${s//|/\\|}"
}

code=${EXIT_CODE:-}
required=${REQUIRED:-}
coverage=${COVERAGE:-}
opted_out=false
case "${REQUIRE_INPUT:-auto}" in [Nn][Oo][Nn][Ee]) opted_out=true ;; esac

report_note() {
  if [ "${REPORT_PRESENT:-}" = "true" ]; then
    printf ' Report: %s.' "$(esc "${REPORT:-}")"
  else
    printf ' No report was written.'
  fi
  if [ "${SARIF_UPLOAD:-}" = "success" ]; then
    printf ' The SARIF report was uploaded to GitHub code scanning.'
  fi
}

# How the requirement stood, in words, for the log line and the summary.
if [ "$opted_out" = true ]; then
  requirement="none: required-analyzer enforcement is off (require-analyzers: none), so coverage is not enforced"
elif [ -n "$required" ]; then
  requirement="${required//,/, }"
else
  requirement="none: require-analyzers is auto and the code input is empty"
fi
if [ -z "$coverage" ]; then
  coverage_text="not reported by the engine"
else
  coverage_text=$coverage
fi

summary() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  local report="not written"
  if [ "${REPORT_PRESENT:-}" = "true" ]; then
    report=$(cell "${REPORT:-}")
    if [ "${SARIF_UPLOAD:-}" = "success" ]; then report="$report (uploaded to code scanning)"; else report="$report (not uploaded)"; fi
  fi
  {
    echo "### Fendix scan"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| Result | $(cell "$1") |"
    echo "| Exit code | $(cell "${code:-none}") |"
    if [ "$opted_out" = true ]; then
      echo "| Required analyzers | **Not enforced**: require-analyzers is none, so this result does not show which analyzers ran |"
    else
      echo "| Required analyzers | $(cell "$requirement")$( [ -n "$required" ] && [ -n "${REQUIRED_RESULT:-}" ] && printf ' (%s)' "$(cell "$REQUIRED_RESULT")") |"
    fi
    echo "| Coverage | $(cell "$coverage_text") |"
    echo "| Report | $report |"
  } >>"$GITHUB_STEP_SUMMARY"
}

complete=false
[ "$coverage" = "complete" ] && complete=true

case "$code" in
  "")
    echo "::error title=Fendix did not run::A setup step failed before the scan, so there is no result to enforce. See the first failed step above."
    summary "Did not run: a setup step failed before the scan (see the first failed step)"
    exit 2
    ;;
  0)
    if [ "$opted_out" = true ]; then
      echo "::warning title=Fendix coverage not enforced::No finding reached BLOCK status, but require-analyzers is none, so required-analyzer enforcement is off and this result does not show that every analyzer ran. Coverage: $(esc "$coverage_text").$(report_note)"
      summary "No finding reached BLOCK status; coverage is not enforced"
    elif [ "$complete" != true ]; then
      echo "::warning title=Fendix coverage incomplete::No finding reached BLOCK status, but coverage was $(esc "$coverage_text"): findings from analyzers that did not run are absent. Required analyzers: $(esc "$requirement").$(report_note)"
      summary "No finding reached BLOCK status; coverage $coverage_text"
    else
      echo "✓ Fendix: no finding reached BLOCK status. Required analyzers: $(esc "$requirement"). Coverage: complete.$(report_note)"
      summary "Passed: no finding reached BLOCK status"
    fi
    exit 0
    ;;
  1)
    echo "::error title=Fendix policy BLOCK::At least one finding reached BLOCK status (fail-on: $(esc "${FAIL_ON:-not set}")). See the scan log above. Coverage: $(esc "$coverage_text").$(report_note)"
    summary "BLOCK: at least one finding reached BLOCK status"
    exit 1
    ;;
  2)
    if [ -n "${REQUIRED_DETAIL:-}" ]; then
      names=${REQUIRED_RESULT:-}
      names=${names#not delivered (}
      names=${names%)}
      [ -n "$names" ] || names=$required
      echo "::error title=Fendix required analyzer $(esc "$names" | sed 's/,/%2C/g') was not delivered::The scan ran, but a required analyzer was not delivered: $(esc "$REQUIRED_DETAIL"). fendix exited 2, so the gate fails closed and the partial report was not uploaded.$(report_note)"
      summary "Failed: required analyzer not delivered ($REQUIRED_DETAIL)"
    else
      echo "::error title=Fendix scan error::The scan did not complete (fendix exited 2). See the scan log above for the cause.$(report_note)"
      summary "Failed: the scan did not complete (fendix exited 2)"
    fi
    exit 2
    ;;
  *)
    echo "::error title=Fendix gate::Unexpected scan exit code '$(esc "$code")'; failing closed. See the scan log above."
    summary "Failed closed: unexpected scan exit code"
    exit 2
    ;;
esac
