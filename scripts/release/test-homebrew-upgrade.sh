#!/bin/sh
# Drives real Homebrew against formulae from render-homebrew-formula.sh, in a
# throwaway local tap, and proves the upgrade path users depend on:
#
#   1. an install recorded as "64" (what older Homebrew made of the release
#      URLs) is not offered v3.5.0 by the formula shape published before
#      this fix: the defect;
#   2. the rendered v3.5.0 formula (version_scheme 1) reports 3.5.0, is
#      outdated against that install, and `brew upgrade` installs it;
#   3. the rendered v3.5.1 formula reports 3.5.1, not 64, v3.5.0 is outdated
#      against it, and `brew upgrade` installs it;
#   4. a fresh install of the v3.5.1 formula works and passes `brew test`;
#   5. the formula passes `brew style` and `brew audit --strict`.
#
# Formulae carry the real release URLs, because Homebrew reads the version
# from them. The binaries are local: each is placed at the path
# `brew --cache` names for the formula, so brew verifies its checksum and
# installs it without downloading, and the test needs no published release.
#
# Run it only where Homebrew may be modified freely (a CI runner or a
# homebrew/brew container): it installs and uninstalls fendix and taps
# fendix-test/fendix. OLD_BIN and NEW_BIN are binaries for this machine's
# platform whose `fendix version` reports v3.5.0 and v3.5.1.
set -eu

: "${OLD_BIN:?set OLD_BIN to a fendix binary that reports v3.5.0}"
: "${NEW_BIN:?set NEW_BIN to a fendix binary that reports v3.5.1}"

ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
RENDER="$ROOT/scripts/release/render-homebrew-formula.sh"
TAP=fendix-test/fendix
FORMULA="$TAP/fendix"
# Install cleanup stays on, as it is for users: brew upgrade removes the
# superseded keg, so `brew list --versions` shows exactly what is installed.
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1

fail() {
    echo "test-homebrew-upgrade: $1" >&2
    exit 1
}
step() { printf '\n== %s\n' "$1"; }

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) PLATFORM=linux-amd64 ;;
    Linux-aarch64 | Linux-arm64) PLATFORM=linux-arm64 ;;
    Darwin-arm64) PLATFORM=darwin-arm64 ;;
    Darwin-x86_64) PLATFORM=darwin-amd64 ;;
    *) fail "unsupported platform $(uname -s)-$(uname -m)" ;;
esac

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

TMP=$(mktemp -d)
cleanup() {
    brew uninstall --force fendix >/dev/null 2>&1 || true
    brew untap "$TAP" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# render <tag> <binary>: this platform gets the binary's checksum; the three
# platforms brew never fetches here get distinct well-formed placeholders.
render() {
    real=$(sha256_file "$2")
    da=1111111111111111111111111111111111111111111111111111111111111111
    dx=2222222222222222222222222222222222222222222222222222222222222222
    la=3333333333333333333333333333333333333333333333333333333333333333
    lx=4444444444444444444444444444444444444444444444444444444444444444
    case "$PLATFORM" in
        darwin-arm64) da=$real ;;
        darwin-amd64) dx=$real ;;
        linux-arm64) la=$real ;;
        linux-amd64) lx=$real ;;
    esac
    sh "$RENDER" "$1" "$da" "$dx" "$la" "$lx"
}
without_scheme() { grep -v '^  version_scheme ' "$1"; }

render v3.5.0 "$OLD_BIN" > "$TMP/v3.5.0.rb"
render v3.5.1 "$NEW_BIN" > "$TMP/v3.5.1.rb"
# The shape published before this fix: same formula, no version_scheme.
without_scheme "$TMP/v3.5.0.rb" > "$TMP/published-v3.5.0.rb"
# An install as older Homebrew recorded it: served from a file:// URL, which
# every Homebrew version reads as "64", exactly as older ones read the
# release URLs.
mkdir -p "$TMP/assets/v3.5.0"
cp "$OLD_BIN" "$TMP/assets/v3.5.0/fendix-v3.5.0-$PLATFORM"
FENDIX_FORMULA_BASE_URL="file://$TMP/assets" render v3.5.0 "$OLD_BIN" > "$TMP/legacy-scheme.rb"
without_scheme "$TMP/legacy-scheme.rb" > "$TMP/legacy.rb"

mkdir -p "$TMP/tapsrc/Formula"
cp "$TMP/legacy.rb" "$TMP/tapsrc/Formula/fendix.rb"
git -C "$TMP/tapsrc" init -q
git -C "$TMP/tapsrc" -c user.name=test -c user.email=test@example.invalid add -A
git -C "$TMP/tapsrc" -c user.name=test -c user.email=test@example.invalid commit -qm "legacy formula"
brew tap "$TAP" "$TMP/tapsrc" >/dev/null
TAPDIR=$(brew --repository "$TAP")
brew trust --formula "$FORMULA" >/dev/null 2>&1 || true

present() { cp "$1" "$TAPDIR/Formula/fendix.rb"; }
# prime <binary>: put the binary where brew will look for the presented
# formula's download.
prime() { cp "$1" "$(brew --cache "$FORMULA")"; }
installed() { brew list --versions fendix; }
stable() { brew info --json=v2 "$FORMULA" | grep -o '"stable": *"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/'; }
outdated() { brew outdated --formula --verbose "$FORMULA" 2>/dev/null || true; }
expect() { [ "$2" = "$3" ] || fail "$1: got '$2', want '$3'"; echo "ok  $1: $2"; }

step "1. an install recorded as 64 is stuck on the formula shape published before this fix"
brew install "$FORMULA" >/dev/null
expect "install recorded as" "$(installed)" "fendix 64"
present "$TMP/published-v3.5.0.rb"
expect "published v3.5.0 formula reports" "$(stable)" "3.5.0"
[ -z "$(outdated)" ] || fail "expected the pre-fix formula NOT to offer an upgrade (the defect); got '$(outdated)'"
echo "ok  brew outdated is empty: 64 ranks above 3.5.0, so no upgrade is offered"

step "2. the rendered v3.5.0 formula (version_scheme 1) recovers that install"
present "$TMP/v3.5.0.rb"
expect "rendered v3.5.0 formula reports" "$(stable)" "3.5.0"
o=$(outdated)
[ -n "$o" ] || fail "brew outdated does not report the 64 install against the rendered v3.5.0 formula"
echo "ok  brew outdated: $o"
prime "$OLD_BIN"
brew upgrade "$FORMULA" >/dev/null
expect "after brew upgrade" "$(installed)" "fendix 3.5.0"
expect "fendix version" "$(fendix version | awk '{print $3}')" "v3.5.0"

step "3. v3.5.0 is outdated against the rendered v3.5.1 formula and brew upgrade installs it"
present "$TMP/v3.5.1.rb"
expect "rendered v3.5.1 formula reports (not 64)" "$(stable)" "3.5.1"
o=$(outdated)
case "$o" in
    *"(3.5.0) < 3.5.1"*) echo "ok  brew outdated: $o" ;;
    *) fail "brew outdated does not report 3.5.0 < 3.5.1 (got '$o')" ;;
esac
prime "$NEW_BIN"
brew upgrade "$FORMULA" >/dev/null
expect "after brew upgrade" "$(installed)" "fendix 3.5.1"
expect "fendix version" "$(fendix version | awk '{print $3}')" "v3.5.1"
[ -z "$(outdated)" ] || fail "fendix still outdated after the upgrade"
echo "ok  nothing outdated after the upgrade"

step "4. fresh install of the rendered v3.5.1 formula"
brew uninstall --force fendix >/dev/null
prime "$NEW_BIN"
brew install "$FORMULA" >/dev/null
expect "fresh install" "$(installed)" "fendix 3.5.1"
expect "fendix version" "$(fendix version | awk '{print $3}')" "v3.5.1"
brew test "$FORMULA" >/dev/null
echo "ok  brew test"

step "5. brew style and brew audit --strict on the rendered v3.5.1 formula"
brew uninstall --force fendix >/dev/null
brew style "$FORMULA"
brew audit --strict "$FORMULA"
echo "ok  brew style, brew audit --strict"

if grep -Eiq 'abdel-rahmansaied' "$TMP/v3.5.0.rb" "$TMP/v3.5.1.rb"; then
    fail "a rendered formula names the retired personal namespace"
fi
echo "ok  rendered formulae carry no personal namespace"

printf '\nhomebrew upgrade checks passed on %s\n' "$PLATFORM"
