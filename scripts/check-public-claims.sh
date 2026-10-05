#!/bin/sh
set -eu

python3 scripts/check-public-claims.py --self-test
python3 scripts/check-public-claims.py

REDIRECT='https://www.fendix.dev/docs/getting-started'
grep -F "http-equiv=\"refresh\" content=\"0; url=${REDIRECT}\"" scripts/release/mirror-pages-bootstrap/index.html >/dev/null
grep -F "rel=\"canonical\" href=\"${REDIRECT}\"" scripts/release/mirror-pages-bootstrap/index.html >/dev/null

# Current Action examples must use the public organization repository.
# grep, not rg: ubuntu-latest has no ripgrep, so an rg check here never ran.
if grep -rniE 'uses:[[:space:]]*abdel-rahmansaied/fendix@' README.md docs --exclude-dir=reviews --exclude-dir=superpowers; then
  echo "retired GitHub Action namespace found in current documentation" >&2
  exit 1
fi

grep -F 'docker.io/fendixapp/fendix' .github/workflows/release.yml >/dev/null
grep -F 'DOCKERHUB_USERNAME' .github/workflows/release.yml >/dev/null
grep -F 'DOCKERHUB_TOKEN' .github/workflows/release.yml >/dev/null

# Current distribution guidance must use the organization-owned tap, release
# repository, and canonical Docker Hub image. Every other spelling of the
# personal namespace, including the historical signer install.sh keeps for
# releases through v3.4.1, is classified by check-public-claims.py above.
set -- README.md docs/install.md docs/INTEGRATION_GUIDE.md scripts/install.sh Formula/fendix.rb .github/workflows/release.yml
if grep -niE \
  'github\.com/Abdel-RahmanSaied/homebrew-fendix|brew tap Abdel-RahmanSaied/fendix|ghcr\.io/abdel-rahmansaied/fendix' \
  "$@"; then
  echo "retired current distribution path found" >&2
  exit 1
fi

grep -F 'brew tap Fendix-app/fendix' README.md >/dev/null
# The Go module identity is what new binaries report in `go version -m`.
grep -Fx 'module github.com/Fendix-app/Fendix/go' go/go.mod >/dev/null
# shellcheck disable=SC2016 # Match the literal shell assignment.
grep -F 'CURRENT_SIGN_REPO="Fendix-app/Fendix"' scripts/install.sh >/dev/null
# shellcheck disable=SC2016 # Match the literal shell assignment.
grep -F 'REPO="${FENDIX_REPO:-Fendix-app/Fendix}"' scripts/install.sh >/dev/null
grep -F 'Fendix-app/homebrew-fendix' .github/workflows/release.yml >/dev/null
grep -F 'fendixapp/fendix@sha256:84feedeb6dce922f9dbe9d8baa78a5fbe056314a606750e012522dd56f01fd7c' README.md >/dev/null
