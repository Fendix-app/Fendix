#!/usr/bin/env sh
# scripts/coverage-smoke-check.sh --deterministic|--network <report.json>
#
# --deterministic  the packaging/capability gate. The report must come from a
#                  scan of tests/fixtures/coverage-smoke run with --offline
#                  against the fixture's own snapshot and with no network at
#                  all. It proves the image contains and can invoke every
#                  runtime capability it promises. Any failure blocks
#                  promotion of the candidate image.
# --network        the live-integration check. The same fixture scanned online:
#                  govulncheck, pip and npm must be ok, or failed with a
#                  transport reason. A transport failure is a warning, not a
#                  release blocker — it is not a property of the image.
set -eu
mode="$1"; report="$2"; fail=0; warn=0

state_of()  { jq -r --arg n "$1" '[.metadata.scanner_status[] | select(.name==$n) | .state]  | first // "MISSING"' "$report"; }
reason_of() { jq -r --arg n "$1" '[.metadata.scanner_status[] | select(.name==$n) | .reason] | first // "none"' "$report"; }
expect_state()  { got=$(state_of "$1");  [ "$got" = "$2" ] || { echo "::error::$1 state is '$got', expected '$2'";  fail=1; }; }
expect_reason() { got=$(reason_of "$1"); [ "$got" = "$2" ] || { echo "::error::$1 reason is '$got', expected '$2'"; fail=1; }; }

case "$mode" in
  --deterministic)
    for name in secrets textscan semgrep pip npm python-engine python-engine/injection python-engine/deps; do
      expect_state "$name" ok
    done
    expect_reason govulncheck disabled_offline
    expect_reason python-engine/auth not_applicable
    expect_reason dast not_applicable
    expect_reason spec not_applicable
    expect_reason active-probes disabled_by_flag
    expect_reason plugins not_applicable
    dm=$(jq -r '[.metadata.scanner_status[] | select(.reason=="dependency_missing") | .name] | join(",")' "$report")
    [ -z "$dm" ] || { echo "::error::dependency_missing inside the image: $dm"; fail=1; }
    [ "$(jq -r '.metadata.coverage.contract_version // "MISSING"' "$report")" = "1" ] || { echo "::error::coverage.contract_version missing"; fail=1; }
    [ "$(jq -r '.metadata.coverage.configured_complete // "MISSING"' "$report")" = "true" ] || { echo "::error::configured_complete is not true; gaps: $(jq -c '.metadata.coverage.gaps' "$report")"; fail=1; }
    [ "$(jq -r '.metadata.policy_version // "MISSING"' "$report")" != "MISSING" ] || { echo "::error::policy_version missing"; fail=1; }
    deps=$(jq '[.findings[] | select(.category=="deps")] | length' "$report")
    [ "$deps" -ge 2 ] || { echo "::error::offline snapshot findings missing: expected >= 2 dependency findings, got $deps"; fail=1; }
    ;;
  --network)
    for name in govulncheck pip npm; do
      st=$(state_of "$name"); rs=$(reason_of "$name")
      case "$st" in
        ok) ;;
        failed)
          case "$rs" in
            network_error|timeout) echo "::warning::$name: live vulnerability database unavailable ($rs); not a packaging defect"; warn=1 ;;
            *) echo "::error::$name failed online with '$rs' (not a transport reason)"; fail=1 ;;
          esac ;;
        *) echo "::error::$name is '$st/$rs' online"; fail=1 ;;
      esac
    done
    ;;
  *) echo "usage: $0 --deterministic|--network <report.json>" >&2; exit 2 ;;
esac

[ "$fail" = 0 ] && echo "coverage smoke ($mode): ok (warnings=$warn)"
exit $fail
