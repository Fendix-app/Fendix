#!/usr/bin/env bash
# Local-mode scan step of the composite Action (action.yml "Run Fendix scan").
#
# Inputs arrive as environment variables and are never interpolated into this
# script: CODE URL SPEC FAIL_ON FORMAT OUTPUT DIFF EXTRA_ARGS, and REQUIRED,
# the analyzers engine preparation resolved from require-analyzers
# (comma-separated, empty for none).
#
# Writes to $GITHUB_OUTPUT:
#   report-present  false before the scan starts; true only when OUTPUT then
#                   exists and is non-empty AND the scan finished (exit 0 or
#                   1): the report the SARIF upload may publish. A partial
#                   report a failed scan left (exit 2, for example a required
#                   analyzer not delivered) is never uploaded, because code
#                   scanning would close every alert missing from it.
#   report-written  true when OUTPUT exists and is non-empty, whatever the
#                   exit code; the gate words its result with it
#   report          the OUTPUT path
#   exit-code       the fendix exit code (2 when the scan could not start)
#   coverage        the engine's coverage verdict ("complete", or
#                   "incomplete (<analyzers>)"); empty when none was printed
#   required-result the engine's verdict on REQUIRED ("satisfied", or
#                   "not delivered (<analyzers>)"); empty when none was printed
#   required-detail why a required analyzer was not delivered, as the engine
#                   words it; empty otherwise
#
# Always exits 0. The job is decided by the gate step (enforce.sh), which runs
# after the SARIF upload so findings are visible even when the gate fails.
set -uo pipefail

echo "report-present=false" >>"$GITHUB_OUTPUT"

# A newline in the path would let the value write outputs of its own.
case "$OUTPUT" in
  *$'\n'* | *$'\r'*)
    echo "::error title=Fendix::The output input must be a single-line path."
    echo "exit-code=2" >>"$GITHUB_OUTPUT"
    exit 0
    ;;
esac

args=()
[ -n "$CODE" ] && args+=(--code "$CODE")
[ -n "$URL" ] && args+=(--url "$URL")
[ -n "$SPEC" ] && args+=(--spec "$SPEC")
[ -n "$FAIL_ON" ] && args+=(--fail-on "$FAIL_ON")
args+=(--format "$FORMAT" --output "$OUTPUT")

# Diff mode: 'auto' on a pull_request event, 'true' on any event. --diff
# limits the native secrets, text and Semgrep scanners to the changed files
# (whole files); the Python engine and DAST still scan everything. A fetch
# error is ignored here; if origin/<base> is then missing, the engine falls
# back to a full scan.
# Requires fetch-depth: 0 on checkout.
if [ "$DIFF" = "true" ] || { [ "$DIFF" = "auto" ] && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; }; then
  base="${GITHUB_BASE_REF:-}"
  if [ -n "$base" ]; then
    git fetch --no-tags --depth=1 origin "$base" 2>/dev/null || true
    args+=(--diff="origin/$base")
  else
    args+=(--diff)
  fi
fi

# Required analyzers go to the engine too, so one that passed the preflight
# and then fails during the scan still exits 2. They come before EXTRA_ARGS:
# a repeated --require-analyzers only adds names, and a flag there that
# disables a required analyzer is a contradiction the engine exits 2 on.
required=${REQUIRED:-}
if [ -n "$required" ]; then
  if ! [[ $required =~ ^[a-z][a-z0-9/-]*(,[a-z][a-z0-9/-]*)*$ ]]; then
    echo "::error title=Fendix require-analyzers::The resolved required analyzers are not a list of analyzer names."
    echo "exit-code=2" >>"$GITHUB_OUTPUT"
    exit 0
  fi
  args+=(--require-analyzers "$required")
fi

# shellcheck disable=SC2206  # intentional word-split into multiple flags
[ -n "$EXTRA_ARGS" ] && args+=($EXTRA_ARGS)

# A file left at OUTPUT by an earlier step must not pass for this scan's report.
rm -f -- "$OUTPUT"

# %q keeps every argument on this one log line, whatever it contains.
printf 'fendix scan'
printf ' %q' "${args[@]}"
printf '\n'
# The output is kept as well as shown, so the gate can state the engine's own
# coverage verdict. The exit code alone still decides the job.
log=$(mktemp "${RUNNER_TEMP:-/tmp}/fendix-scan.XXXXXXXX")
fendix scan "${args[@]}" 2>&1 | tee "$log"
code=${PIPESTATUS[0]}

written=false
[ -s "$OUTPUT" ] && written=true
present=false
if [ "$written" = true ] && { [ "$code" = 0 ] || [ "$code" = 1 ]; }; then present=true; fi

# The engine prints these at the end of every scan. The last match wins, so a
# line some analyzer echoed earlier cannot stand in for the verdict.
verdict() {
  local line last=""
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in "$1"*) last=${line#"$1"} ;; esac
  done <"$log"
  printf '%s' "$last"
}
{
  echo "report=$OUTPUT"
  echo "exit-code=$code"
  echo "report-present=$present"
  echo "report-written=$written"
  echo "coverage=$(verdict 'coverage: ')"
  echo "required-result=$(verdict 'required: ')"
  echo "required-detail=$(verdict 'fendix: required analyzer(s) not delivered: ')"
} >>"$GITHUB_OUTPUT"
rm -f -- "$log"
exit 0
