#!/bin/sh
# Static checks for scripts/release/render-homebrew-formula.sh. Needs no
# Homebrew; scripts/release/test-homebrew-upgrade.sh covers brew's own
# behaviour against the rendered formula.
set -eu

ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
RENDER="$ROOT/scripts/release/render-homebrew-formula.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

fail() {
    echo "test-homebrew-formula: $1" >&2
    exit 1
}

DA=1111111111111111111111111111111111111111111111111111111111111111
DX=2222222222222222222222222222222222222222222222222222222222222222
LA=3333333333333333333333333333333333333333333333333333333333333333
LX=4444444444444444444444444444444444444444444444444444444444444444
sh "$RENDER" v3.5.1 "$DA" "$DX" "$LA" "$LX" > "$TMP/fendix.rb"
F="$TMP/fendix.rb"

# version_scheme 1 ranks every release above installs older Homebrew
# recorded as "64". There is no explicit version: Homebrew reads it from the
# tag in each URL, and brew audit --strict rejects a redundant one.
[ "$(grep -cFx '  version_scheme 1' "$F")" -eq 1 ] || fail 'want exactly one: version_scheme 1'
if grep -q '^ *version "' "$F"; then
    fail "formula declares an explicit version; brew audit --strict rejects it as redundant with the URL"
fi

# Every platform keeps its own release URL, carrying the tag Homebrew reads
# the version from, and on the next line its own checksum.
for pair in "darwin-arm64 $DA" "darwin-amd64 $DX" "linux-arm64 $LA" "linux-amd64 $LX"; do
    platform=${pair% *}
    sha=${pair#* }
    url="https://github.com/Fendix-app/Fendix/releases/download/v3.5.1/fendix-v3.5.1-${platform}"
    grep -A1 -Fx "      url \"${url}\"" "$F" | grep -Fxq "      sha256 \"${sha}\"" ||
        fail "${platform}: url ${url} is not followed by sha256 ${sha}"
done
[ "$(grep -c '^ *url "' "$F")" -eq 4 ] || fail "want exactly four platform URLs"

if grep -Eiq 'abdel-rahmansaied' "$F"; then
    fail "formula names the retired personal namespace"
fi

if command -v ruby >/dev/null 2>&1; then
    ruby -c "$F" >/dev/null || fail "rendered formula is not valid Ruby"
fi

# Inputs the mirror job must never publish are refused.
for bad in "3.5.1 $DA $DX $LA $LX" "v3.5.1-rc.1 $DA $DX $LA $LX" "v3.5.1 $DA $DX $LA" \
    "v3.5.1 $DA $DX $LA ABCDEF" "v3.5.1 $DA $DX $LA 4444"; do
    # shellcheck disable=SC2086 # split the case into arguments
    if sh "$RENDER" $bad > /dev/null 2>&1; then
        fail "renderer accepted: $bad"
    fi
done

# Formula/fendix.rb is the renderer's output for its own tag and checksums,
# so the published formula and the copy in this repo cannot drift.
REPO_FORMULA="$ROOT/Formula/fendix.rb"
tag=$(sed -n 's#^ *url "https://github.com/Fendix-app/Fendix/releases/download/\(v[^/]*\)/.*#\1#p' "$REPO_FORMULA" | sort -u)
[ "$(printf '%s\n' "$tag" | wc -l | tr -d ' ')" -eq 1 ] || fail "Formula/fendix.rb mixes release tags: $tag"
shas=$(sed -n 's#^ *sha256 "\([0-9a-f]*\)"#\1#p' "$REPO_FORMULA")
# shellcheck disable=SC2086 # four checksums, in formula order
sh "$RENDER" "$tag" $shas > "$TMP/expected.rb"
diff -u "$TMP/expected.rb" "$REPO_FORMULA" ||
    fail "Formula/fendix.rb differs from render-homebrew-formula.sh output for ${tag}"

echo "homebrew formula checks passed (version_scheme, no explicit version, 4 platform URL/SHA pairs, inputs, Formula/fendix.rb in sync with ${tag})"
