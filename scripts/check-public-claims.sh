#!/bin/sh
set -eu

# Keep the retired "both engines must confirm" marketing rule from returning.
# Correlation can raise confidence, but current policy may also block a strong,
# deterministic single-source finding; coverage gaps are a separate INCOMPLETE
# outcome.
if rg -n -i \
  'fails?( the build)? only when both engines confirm|both engines must agree|runtime probe and static analysis must agree before fendix fails|multiple engines confirm a vulnerability|findings only fail ci when both engines confirm|only (confirmed, )?correlated(, reachable)? findings block' \
  README.md docs scripts/release/mirror-pages-bootstrap; then
  echo "obsolete multi-engine-only claim found" >&2
  exit 1
fi

REDIRECT='https://www.fendix.dev/docs/getting-started'
grep -F "http-equiv=\"refresh\" content=\"0; url=${REDIRECT}\"" scripts/release/mirror-pages-bootstrap/index.html >/dev/null
grep -F "rel=\"canonical\" href=\"${REDIRECT}\"" scripts/release/mirror-pages-bootstrap/index.html >/dev/null

# Current Action examples must use the public organization repository.
if rg -n -i 'uses:\s*abdel-rahmansaied/fendix@' README.md docs --glob '!reviews/**' --glob '!superpowers/**'; then
  echo "retired GitHub Action namespace found in current documentation" >&2
  exit 1
fi

grep -F 'docker.io/fendixapp/fendix' .github/workflows/release.yml >/dev/null
grep -F 'DOCKERHUB_USERNAME' .github/workflows/release.yml >/dev/null
grep -F 'DOCKERHUB_TOKEN' .github/workflows/release.yml >/dev/null
