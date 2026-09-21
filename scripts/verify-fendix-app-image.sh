#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <image-ref> <linux/amd64|linux/arm64> <expected-version> <artifact-dir>" >&2
  exit 2
}

[ "$#" -eq 4 ] || usage

image_ref=$1
platform=$2
expected_version=$3
artifact_dir=$4

case "$platform" in
  linux/amd64|linux/arm64) ;;
  *) usage ;;
esac

mkdir -p "$artifact_dir"
arch=${platform#linux/}
container_name="fendix-app-smoke-${arch}-$$"
key_file="$(mktemp "${TMPDIR:-/tmp}/fendix-app-key.XXXXXX.pem")"
runtime_canary="fendix-app-smoke-$(openssl rand -hex 24)"

cleanup() {
  docker stop "$container_name" >/dev/null 2>&1 || true
  docker container rm "$container_name" >/dev/null 2>&1 || true
  # Truncate generated key material before leaving the ephemeral runner.
  : > "$key_file"
  rm -f "$key_file"
}
trap cleanup EXIT HUP INT TERM

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$key_file" >/dev/null 2>&1
chmod 0644 "$key_file"
key_canary=$(sed -n '2p' "$key_file")

if [ "${FENDIX_SKIP_PULL:-0}" != "1" ]; then
  docker pull --platform "$platform" "$image_ref" >/dev/null
fi
docker run -d \
  --platform "$platform" \
  --name "$container_name" \
  -p 127.0.0.1::8080 \
  -e FENDIX_APP_ID=1234567 \
  -e FENDIX_APP_PRIVATE_KEY_FILE=/run/secrets/test-private-key.pem \
  -e FENDIX_WEBHOOK_SECRET="$runtime_canary" \
  -v "$key_file:/run/secrets/test-private-key.pem:ro" \
  "$image_ref" >/dev/null

port=$(docker port "$container_name" 8080/tcp | sed 's/.*://')
health_file="$artifact_dir/healthz-${arch}.txt"
curl --fail --silent --show-error --retry 15 --retry-delay 1 \
  --retry-connrefused --retry-all-errors \
  "http://127.0.0.1:${port}/healthz" > "$health_file"
grep -Fx "fendix-app ${expected_version}" "$health_file" >/dev/null

docker logs "$container_name" > "$artifact_dir/container-${arch}.log" 2>&1
docker image inspect "$image_ref" > "$artifact_dir/image-config-${arch}.json"
docker history --no-trunc "$image_ref" > "$artifact_dir/image-history-${arch}.txt"
docker image save "$image_ref" -o "$artifact_dir/image-${arch}.tar"

# Search exact ephemeral/runtime and signing credentials without printing them.
# The image intentionally contains scanner fixtures and credential-detection
# regexes, so broad pattern matching inside layers would report those harmless
# canaries. Exact secret-value checks distinguish leakage from scanner data.
for file in "$artifact_dir"/*; do
  [ -f "$file" ] || continue
  if grep -aFq "$runtime_canary" "$file"; then
    echo "credential leakage: runtime canary found in $(basename "$file")" >&2
    exit 1
  fi
  if grep -aFq "$key_canary" "$file"; then
    echo "credential leakage: private-key material found in $(basename "$file")" >&2
    exit 1
  fi
done

# Configuration, history, build output and logs must not contain a concrete
# credential assignment. Placeholder names and scanner rules remain allowed.
for file in \
  "$artifact_dir/image-config-${arch}.json" \
  "$artifact_dir/image-history-${arch}.txt" \
  "$artifact_dir/container-${arch}.log" \
  "$artifact_dir/build.log"; do
  [ -f "$file" ] || continue
  if grep -aEiq '(password|token|secret|private[_-]?key)=[A-Za-z0-9_+/=-]{12,}' "$file"; then
    echo "credential-pattern match found in $(basename "$file")" >&2
    exit 1
  fi
done

rm -f "$artifact_dir/image-${arch}.tar"

echo "fendix-app ${platform} startup, health and credential scan: PASS"
