#!/bin/sh
# Runs the CircleCI config `fendix init --ci circleci` writes, step by step
# and verbatim, in CircleCI's own cimg/base image as its circleci user, and
# proves the signature requirement holds end to end:
#
#   1. the generated steps install a checksum-pinned cosign, then a signed
#      release, with the installer requiring the signature;
#   2. without the Install cosign step, Install Fendix refuses instead of
#      falling back to the checksum;
#   3. a release published without .sig/.crt is refused;
#   4. a cosign download that does not match the pin stops the job before
#      Fendix is installed;
#   5. nothing generated or printed names the retired personal namespace.
#
# Needs docker and network (GitHub releases, Sigstore). FENDIX_BIN is a
# fendix binary for this machine, used only to run `fendix init`.
# INSTALL_VERSION (default v3.5.0) replaces the generated FENDIX_VERSION with
# a published, signed release. INSTALLER_COMMIT, when set, replaces the
# generated FENDIX_INSTALLER_COMMIT with a pushed commit, for builds whose
# own commit raw.githubusercontent.com cannot serve.
set -eu

: "${FENDIX_BIN:?set FENDIX_BIN to a fendix binary that can run on this machine}"
INSTALL_VERSION=${INSTALL_VERSION:-v3.5.0}
IMAGE=${CIRCLECI_IMAGE:-cimg/base:current}

fail() {
    echo "test-circleci-install: $1" >&2
    exit 1
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
(cd "$TMP" && "$FENDIX_BIN" init --ci circleci > init-output.txt)
chmod -R a+rX "$TMP"

# Inside the container: load the job's environment from the generated
# config, apply the case's overrides, and run the named steps exactly as
# CircleCI does (bash -eo pipefail).
cat > "$TMP/run-job.sh" <<'JOB'
#!/bin/bash
set -euo pipefail
cfg=/work/.circleci/fendix-config.yml
eval "$(yq -o=shell '.jobs["fendix-scan"].environment' "$cfg" | sed 's/^/export /')"
export FENDIX_VERSION="$CASE_VERSION"
if [ -n "${INSTALLER_COMMIT:-}" ]; then export FENDIX_INSTALLER_COMMIT="$INSTALLER_COMMIT"; fi
if [ -n "${CASE_COSIGN_SHA:-}" ]; then
  export COSIGN_SHA256_LINUX_AMD64="$CASE_COSIGN_SHA" COSIGN_SHA256_LINUX_ARM64="$CASE_COSIGN_SHA"
fi
step() { yq ".jobs[\"fendix-scan\"].steps[] | select(.run.name == \"$1\") | .run.command" "$cfg"; }
cd "$HOME"
if [ "${SKIP_COSIGN:-0}" != 1 ]; then
  bash -eo pipefail -c "$(step 'Install cosign')"
fi
bash -eo pipefail -c "$(step 'Install Fendix')"
JOB

# run_case <name> [VAR=value ...]: runs the job in a fresh container and
# records its exit code and output.
run_case() {
    name=$1
    shift
    set -- -e CASE_VERSION="$INSTALL_VERSION" -e INSTALLER_COMMIT="${INSTALLER_COMMIT:-}" "$@"
    if docker run --rm -u circleci -v "$TMP:/work:ro" "$@" "$IMAGE" bash /work/run-job.sh > "$TMP/$name.log" 2>&1; then
        echo 0 > "$TMP/$name.code"
    else
        echo $? > "$TMP/$name.code"
    fi
}
expect_exit() {
    code=$(cat "$TMP/$1.code")
    case "$2" in
        0) [ "$code" -eq 0 ] || { cat "$TMP/$1.log" >&2; fail "$1: exited $code, want success"; } ;;
        nonzero) [ "$code" -ne 0 ] || { cat "$TMP/$1.log" >&2; fail "$1: succeeded, want a refusal"; } ;;
    esac
}
expect_log() {
    grep -Fq -- "$2" "$TMP/$1.log" || { cat "$TMP/$1.log" >&2; fail "$1: output lacks '$2'"; }
}
reject_log() {
    if grep -Fq -- "$2" "$TMP/$1.log"; then
        cat "$TMP/$1.log" >&2
        fail "$1: output contains '$2'"
    fi
}

echo "== 1. generated steps: pinned cosign, then a signed $INSTALL_VERSION with the signature required"
run_case signed
expect_exit signed 0
expect_log signed "cosign: OK"
expect_log signed "cosign signature verified."
expect_log signed "fendix version $INSTALL_VERSION "
echo "ok  cosign checksum OK, release signature verified, fendix $INSTALL_VERSION installed"

echo "== 2. without the Install cosign step, Install Fendix refuses"
run_case no-cosign -e SKIP_COSIGN=1
expect_exit no-cosign nonzero
expect_log no-cosign "FENDIX_REQUIRE_SIGNATURE=1 but cosign is not installed. Refusing to install."
reject_log no-cosign "Installed fendix"
echo "ok  refused: cosign is not installed"

echo "== 3. a release without .sig/.crt is refused"
# v0.6.0-rc1 predates release signing and ships linux-amd64 and linux-arm64.
run_case unsigned -e CASE_VERSION=v0.6.0-rc1
expect_exit unsigned nonzero
expect_log unsigned "FENDIX_REQUIRE_SIGNATURE=1 but release v0.6.0-rc1 has no .sig/.crt. Refusing to install."
reject_log unsigned "Installed fendix"
echo "ok  refused: v0.6.0-rc1 carries no signature"

echo "== 4. a cosign download that does not match the pin stops the job"
run_case bad-cosign -e CASE_COSIGN_SHA=0000000000000000000000000000000000000000000000000000000000000000
expect_exit bad-cosign nonzero
expect_log bad-cosign "cosign: FAILED"
reject_log bad-cosign "Downloading fendix"
echo "ok  refused before Fendix was downloaded"

echo "== 5. no retired personal namespace in generated files or job output"
if grep -rEiq 'abdel-rahmansaied' "$TMP"; then
    grep -rEil 'abdel-rahmansaied' "$TMP" >&2
    fail "the retired personal namespace appears above"
fi
echo "ok  0 occurrences"

printf '\ncircleci install checks passed in %s (%s)\n' "$IMAGE" "$(docker run --rm "$IMAGE" uname -m)"
