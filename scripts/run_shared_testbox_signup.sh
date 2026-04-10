#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd -P)
SQLITE_SNAPSHOT="$SCRIPT_DIR/sqlite-snapshot.sh"
TEMP_UPLOADS=()
PREPARED_UPLOAD_PATH=""

cleanup() {
  if [ "${#TEMP_UPLOADS[@]}" -eq 0 ]; then
    return
  fi

  for temp_path in "${TEMP_UPLOADS[@]}"; do
    rm -f "$temp_path"
  done
}

prepare_extra_upload_path() {
  local source_path="$1"
  local target_extra="$2"
  local upload_path="$source_path"

  if [ "${target_extra##*.}" = "sqlite" ]; then
    upload_path="$(mktemp "${TMPDIR:-/tmp}/tavreg-testbox-sqlite.XXXXXX")"
    rm -f "$upload_path"
    "$SQLITE_SNAPSHOT" "$source_path" "$upload_path"
    TEMP_UPLOADS+=("$upload_path")
  elif [ "$target_extra" = ".env.local" ] && [ -L "$source_path" ]; then
    upload_path="$(mktemp "${TMPDIR:-/tmp}/tavreg-testbox-env.XXXXXX")"
    rm -f "$upload_path"
    cp -L "$source_path" "$upload_path"
    TEMP_UPLOADS+=("$upload_path")
  fi

  PREPARED_UPLOAD_PATH="$upload_path"
}

main() {
  local TESTBOX="${TESTBOX:-codex-testbox}"
  local IMAGE="${TESTBOX_IMAGE:-mcr.microsoft.com/playwright:v1.58.2-noble}"
  local CHROME_PATH="${TESTBOX_CHROME_PATH:-/work/.tools/fingerprint-browser/linux/chrome}"
  local RUN_MODE="${RUN_MODE:-headed}"
  local BROWSER_ENGINE="${BROWSER_ENGINE:-chrome}"
  local CHROME_NATIVE_AUTOMATION="${CHROME_NATIVE_AUTOMATION:-false}"
  local NEED="${NEED:-1}"
  local PARALLEL="${PARALLEL:-1}"
  local RUN_MODE_Q
  local BROWSER_ENGINE_Q
  local CHROME_NATIVE_AUTOMATION_Q
  local CHROME_PATH_Q
  local NEED_Q
  local PARALLEL_Q
  local REPO_ROOT
  local REPO_NAME
  local PATH_HASH8
  local GIT_SHA
  local RUN_ID
  local WORKSPACE_SLUG
  local REMOTE_BASE
  local REMOTE_WORKSPACE
  local REMOTE_RUN
  local LOCAL_FINGERPRINT_BROWSER_ROOT
  local LOCAL_FINGERPRINT_BROWSER_CACHE
  local run_exit
  local status_ok

  trap cleanup EXIT

  printf -v RUN_MODE_Q '%q' "$RUN_MODE"
  printf -v BROWSER_ENGINE_Q '%q' "$BROWSER_ENGINE"
  printf -v CHROME_NATIVE_AUTOMATION_Q '%q' "$CHROME_NATIVE_AUTOMATION"
  printf -v CHROME_PATH_Q '%q' "$CHROME_PATH"
  printf -v NEED_Q '%q' "$NEED"
  printf -v PARALLEL_Q '%q' "$PARALLEL"

  REPO_ROOT="$(git rev-parse --show-toplevel)"
  REPO_ROOT="$(python3 - "$REPO_ROOT" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
)"
  REPO_NAME="$(basename "$REPO_ROOT")"
  PATH_HASH8="$(python3 - "$REPO_ROOT" <<'PY'
import hashlib, os, sys
print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest()[:8])
PY
)"
  GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
  RUN_ID="${RUN_ID:-$(date -u +%Y%m%d_%H%M%S)_$GIT_SHA}"
  WORKSPACE_SLUG="${REPO_NAME}__${PATH_HASH8}"
  REMOTE_BASE="/srv/codex/workspaces/$USER"
  REMOTE_WORKSPACE="$REMOTE_BASE/$WORKSPACE_SLUG"
  REMOTE_RUN="$REMOTE_WORKSPACE/runs/$RUN_ID"

  echo "[local] repo=$REPO_ROOT"
  echo "[local] remote_run=$REMOTE_RUN"

  LOCAL_FINGERPRINT_BROWSER_ROOT="$REPO_ROOT/.tools/fingerprint-browser/linux"
  LOCAL_FINGERPRINT_BROWSER_CACHE="$REPO_ROOT/downloads/fingerprint-browser"
  echo "[local] ensuring linux fingerprint browser at $LOCAL_FINGERPRINT_BROWSER_ROOT"
  bash "$REPO_ROOT/scripts/install-fingerprint-browser.sh" \
    --platform linux \
    --dest "$LOCAL_FINGERPRINT_BROWSER_ROOT" \
    --cache-dir "$LOCAL_FINGERPRINT_BROWSER_CACHE"


  ssh -o BatchMode=yes "$TESTBOX" "mkdir -p '$REMOTE_RUN' '$REMOTE_RUN/.tools/fingerprint-browser'"

  rsync -az --delete \
    --exclude '.git/' \
    --exclude 'node_modules/' \
    --exclude '.tools/' \
    --exclude 'output/' \
    --exclude 'downloads/' \
    --exclude 'dist/' \
    --exclude 'build/' \
    --exclude '.next/' \
    --exclude '.DS_Store' \
    "$REPO_ROOT/" "$TESTBOX:$REMOTE_RUN/"

  rsync -az \
    "$LOCAL_FINGERPRINT_BROWSER_ROOT/" "$TESTBOX:$REMOTE_RUN/.tools/fingerprint-browser/linux/"

  for extra in \
    ".env.local" \
    "output/registry/tavreg-hikari.sqlite" \
    "output/proxy/node-usage.json" \
    "downloads/mihomo/subscription-cache"; do
    local source_extra="$extra"
    local target_extra="$extra"
    local source_path
    local upload_path

    if [ "$extra" = "output/registry/tavreg-hikari.sqlite" ] && [ ! -e "$REPO_ROOT/$source_extra" ] && [ -e "$REPO_ROOT/output/registry/signup-tasks.sqlite" ]; then
      source_extra="output/registry/signup-tasks.sqlite"
    fi

    source_path="$REPO_ROOT/$source_extra"
    if [ -e "$source_path" ] || [ -L "$source_path" ]; then
      prepare_extra_upload_path "$source_path" "$target_extra"
      upload_path="$PREPARED_UPLOAD_PATH"
      ssh -o BatchMode=yes "$TESTBOX" "mkdir -p '$REMOTE_RUN/$(dirname "$target_extra")'"
      rsync -az "$upload_path" "$TESTBOX:$REMOTE_RUN/$target_extra"
    fi
  done

  ssh -o BatchMode=yes "$TESTBOX" "cat > '$REMOTE_RUN/run-remote-test.sh' <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cd /work
echo \"[\$(date -u +%Y-%m-%dT%H:%M:%SZ)] starting remote registration test (shared-testbox)\" >> remote-test.log
node --version >> remote-test.log 2>&1
if [ ! -d node_modules ]; then
  npm install --package-lock=false >> remote-test.log 2>&1
fi
if [ ! -x /work/.tools/fingerprint-browser/linux/chrome ]; then
  echo "missing preinstalled fingerprint browser: /work/.tools/fingerprint-browser/linux/chrome" >> remote-test.log
  exit 1
fi
run_exit=0
if ! xvfb-run -a env \\
  RUN_MODE=${RUN_MODE_Q} \\
  BROWSER_ENGINE=${BROWSER_ENGINE_Q} \\
  CHROME_NATIVE_AUTOMATION=${CHROME_NATIVE_AUTOMATION_Q} \\
  CHROME_EXECUTABLE_PATH=${CHROME_PATH_Q} \\
  node --import tsx src/main.ts --mode ${RUN_MODE_Q} --need ${NEED_Q} --parallel ${PARALLEL_Q} >> remote-test.log 2>&1; then
  run_exit=\$?
fi
python3 - <<'PY' > remote-test-status.json
import json, pathlib
run = pathlib.Path('/work')
output = run / 'output'
status = {
  'ok': (output / 'result.json').exists(),
  'has_result': (output / 'result.json').exists(),
  'has_error': (output / 'error.json').exists(),
  'has_summary': (output / 'run_summary.json').exists(),
}
if status['has_result']:
  status['result'] = json.loads((output / 'result.json').read_text())
elif status['has_error']:
  status['error'] = json.loads((output / 'error.json').read_text())
print(json.dumps(status, ensure_ascii=False, indent=2))
PY
exit \"\$run_exit\"
SH
chmod +x '$REMOTE_RUN/run-remote-test.sh'"

  run_exit=0
  if ! ssh -o BatchMode=yes "$TESTBOX" "uid=\$(id -u); gid=\$(id -g); docker run --rm --init --cap-drop=all -u \${uid}:\${gid} -v '$REMOTE_RUN:/work' -w /work --env-file '$REMOTE_RUN/.env.local' '$IMAGE' bash /work/run-remote-test.sh"; then
    run_exit=$?
  fi

  echo "[local] remote status"
  ssh -o BatchMode=yes "$TESTBOX" "cat '$REMOTE_RUN/remote-test-status.json'"

  status_ok="$(ssh -o BatchMode=yes "$TESTBOX" "python3 - <<'PY'
import json, pathlib
path = pathlib.Path('$REMOTE_RUN/remote-test-status.json')
if not path.exists():
    print('missing')
else:
    print('true' if json.loads(path.read_text()).get('ok') else 'false')
PY")"

  if [ "$status_ok" = "true" ]; then
    exit 0
  fi

  if [ "$run_exit" -ne 0 ]; then
    exit "$run_exit"
  fi
  exit 1
}

if [ "${RUN_SHARED_TESTBOX_SOURCE_ONLY:-0}" = "1" ]; then
  return 0 2>/dev/null || exit 0
fi

main "$@"
