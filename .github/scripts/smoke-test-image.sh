#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG="${1:?usage: smoke-test-image.sh <image-tag>}"
SMOKE_PORT="${SMOKE_PORT:-37170}"
SMOKE_TIMEOUT_SECS="${SMOKE_TIMEOUT_SECS:-90}"
SMOKE_CONTAINER_NAME="${SMOKE_CONTAINER_NAME:-smoke-tavreg-hikari-${RANDOM}}"
SMOKE_PLATFORM="${SMOKE_PLATFORM:-linux/amd64}"

cleanup() {
  docker rm -f "${SMOKE_CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

docker run -d \
  --name "${SMOKE_CONTAINER_NAME}" \
  --platform "${SMOKE_PLATFORM}" \
  --cap-drop=all \
  -e WEB_HOST=0.0.0.0 \
  -e WEB_PORT=3717 \
  -e RUN_MODE=headless \
  -p "${SMOKE_PORT}:3717" \
  "${IMAGE_TAG}" >/dev/null

start_ts="$(date +%s)"
while true; do
  if curl -fsS "http://127.0.0.1:${SMOKE_PORT}/api/health" | grep -q '"ok":true'; then
    break
  fi

  now_ts="$(date +%s)"
  if (( now_ts - start_ts >= SMOKE_TIMEOUT_SECS )); then
    echo "[smoke-test-image] health check timed out for ${IMAGE_TAG}" >&2
    docker logs "${SMOKE_CONTAINER_NAME}" >&2 || true
    exit 1
  fi
  sleep 2
done

docker exec "${SMOKE_CONTAINER_NAME}" bash -lc '
  set -euo pipefail
  printenv CHROME_EXECUTABLE_PATH
  test -x /opt/fingerprint-browser/chrome
  node /app/scripts/smoke-fingerprint-browser.mjs /opt/fingerprint-browser/chrome
' >/dev/null || {
  echo "[smoke-test-image] browser smoke failed for ${IMAGE_TAG}" >&2
  docker logs "${SMOKE_CONTAINER_NAME}" >&2 || true
  exit 1
}

echo "[smoke-test-image] health + browser smoke passed for ${IMAGE_TAG}"
