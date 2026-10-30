#!/bin/sh
# Verify the digest pinned in the Dockerfile's FROM line against the official registry.
#
# The manifest is fetched by digest, not by tag, and its SHA-256 is recomputed locally. A
# match means the content served for that digest is the content the digest names. The check
# needs no Docker daemon. It exits non-zero on any mismatch or fetch failure.
#
# Usage: scripts/verify_base_image.sh [Dockerfile]
set -eu

DOCKERFILE="${1:-Dockerfile}"
FROM_LINE=$(grep -E '^FROM ' "$DOCKERFILE" | head -n 1)
IMAGE=$(echo "$FROM_LINE" | sed -E 's/^FROM +([^ @]+).*/\1/')
DIGEST=$(echo "$FROM_LINE" | sed -nE 's/.*@(sha256:[0-9a-f]{64}).*/\1/p')

if [ -z "$DIGEST" ]; then
    echo "FAIL: $DOCKERFILE FROM line is not pinned by digest: $FROM_LINE" >&2
    exit 1
fi

REPO="${IMAGE%%:*}"
case "$REPO" in
    */*) ;;
    *) REPO="library/$REPO" ;;
esac

# Retry only transient failures (HTTP 429 and 5xx) with backoff. Other failures are final.
fetch() {
    code=$(curl -sS -o "$BODY" -w '%{http_code}' "$@") || return 1
    case "$code" in
        200) return 0 ;;
        429|5??) return 75 ;;
        *) echo "HTTP $code from $1" >&2; return 1 ;;
    esac
}

fetch_with_retry() {
    attempt=1
    delay=5
    while :; do
        status=0
        fetch "$@" || status=$?
        [ "$status" -ne 75 ] && return "$status"
        if [ "$attempt" -ge 5 ]; then
            return 1
        fi
        echo "transient failure, retrying in ${delay}s (attempt $attempt)" >&2
        sleep "$delay"
        attempt=$((attempt + 1))
        delay=$((delay * 2))
    done
}

ACCEPT="application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT

if [ -n "${VERIFY_BODY_FILE:-}" ]; then
    # Test hook: verify a saved manifest body without contacting the registry.
    cp "$VERIFY_BODY_FILE" "$BODY"
else
    TOKEN=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPO}:pull" \
        | sed -nE 's/.*"token" *: *"([^"]+)".*/\1/p')
    [ -n "$TOKEN" ] || { echo "FAIL: no registry token" >&2; exit 1; }
    fetch_with_retry -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" \
        "https://registry-1.docker.io/v2/${REPO}/manifests/${DIGEST}"
fi

ACTUAL="sha256:$(sha256sum "$BODY" | cut -d' ' -f1)"
if [ "$ACTUAL" != "$DIGEST" ]; then
    echo "FAIL: manifest for $DIGEST hashes to $ACTUAL" >&2
    exit 1
fi

echo "OK: $IMAGE pinned to $DIGEST; the registry manifest hashes to the same value."
