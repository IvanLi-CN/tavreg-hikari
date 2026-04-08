#!/bin/sh
set -eu

ZERO_OID=0000000000000000000000000000000000000000
MAIN_ROOT_KEY=codex.worktree-sync.main-root
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
MANIFEST_PATH="$SCRIPT_DIR/worktree-sync.paths"
SQLITE_SNAPSHOT="$SCRIPT_DIR/sqlite-snapshot.sh"
FORCE_SYNC=${WORKTREE_SYNC_FORCE:-0}
DRY_RUN=${WORKTREE_SYNC_DRY_RUN:-0}

log() {
  printf 'worktree-sync: %s\n' "$*"
}

bootstrap_dependencies() {
  deps_stamp_dir="$git_dir/codex-worktree-sync"
  deps_stamp_path="$deps_stamp_dir/deps.stamp"

  if [ ! -f "$current_root/package.json" ]; then
    log "skip dependency install: package.json missing"
    return 0
  fi

  if ! command -v bun >/dev/null 2>&1; then
    log "skip dependency install: bun unavailable"
    return 0
  fi

  install_cmd="bun install"
  if [ -f "$current_root/bun.lock" ]; then
    install_cmd="bun install --frozen-lockfile"
  else
    install_cmd="bun install --no-save"
  fi

  mkdir -p "$deps_stamp_dir"
  deps_signature="install=$install_cmd package=$(cksum < "$current_root/package.json" | awk '{print $1 ":" $2}')"
  if [ -f "$current_root/bun.lock" ]; then
    deps_signature="$deps_signature lock=$(cksum < "$current_root/bun.lock" | awk '{print $1 ":" $2}')"
  fi

  if [ -d "$current_root/node_modules" ] && [ -f "$deps_stamp_path" ] && [ "$(cat "$deps_stamp_path")" = "$deps_signature" ]; then
    log "keep dependency install: node_modules exists"
    return 0
  fi

  if [ "$DRY_RUN" = "1" ]; then
    log "would install dependencies: $install_cmd"
    return 0
  fi

  log "installing dependencies: $install_cmd"
  if ! (
    cd "$current_root"
    case "$install_cmd" in
      "bun install --frozen-lockfile")
        bun install --frozen-lockfile
        ;;
      "bun install --no-save")
        bun install --no-save
        ;;
      *)
        bun install
        ;;
    esac
  ); then
    rm -f "$deps_stamp_path"
    log "skip dependency install failed: $install_cmd"
    return 0
  fi
  printf '%s\n' "$deps_signature" > "$deps_stamp_path"
  log "installed dependencies"
}

snapshot_sqlite() {
  src_path=$1
  tmp_path=$2
  "$SQLITE_SNAPSHOT" "$src_path" "$tmp_path"
}

canonical_dir() {
  CDPATH= cd -- "$1" && pwd -P
}

canonical_path() {
  target=$1
  parent=$(dirname -- "$target")
  base=$(basename -- "$target")
  printf '%s/%s\n' "$(canonical_dir "$parent")" "$base"
}

resolve_git_path() {
  git_path=$(git rev-parse "$@")
  case "$git_path" in
    /*) printf '%s\n' "$git_path" ;;
    *) canonical_path "$git_path" ;;
  esac
}

read_recorded_main_root() {
  recorded_root=$(git config --path --get "$MAIN_ROOT_KEY" 2>/dev/null || true)
  if [ -z "$recorded_root" ] || [ ! -d "$recorded_root" ]; then
    return 1
  fi
  canonical_dir "$recorded_root"
}

discover_main_root() {
  current_root=$1
  git_dir=$(resolve_git_path --git-dir)
  common_dir=$(resolve_git_path --git-common-dir)

  recorded_root=$(read_recorded_main_root || true)
  if [ -n "$recorded_root" ]; then
    printf '%s\n' "$recorded_root"
    return 0
  fi

  if [ "$git_dir" = "$common_dir" ]; then
    printf '%s\n' "$current_root"
    return 0
  fi

  listed_root=$(git worktree list --porcelain 2>/dev/null | awk '
    index($0, "worktree ") == 1 {
      print substr($0, 10)
      exit
    }
  ')
  if [ -n "$listed_root" ]; then
    canonical_dir "$listed_root"
    return 0
  fi

  if [ "$(basename -- "$common_dir")" = ".git" ]; then
    canonical_dir "$common_dir/.."
    return 0
  fi

  return 1
}

copy_resource() {
  rel_path=$1
  dst_path="$current_root/$rel_path"
  src_rel_path="$rel_path"
  src_path="$source_root/$src_rel_path"

  if [ "$rel_path" = "output/registry/tavreg-hikari.sqlite" ] \
    && [ ! -e "$src_path" ] && [ ! -L "$src_path" ] \
    && { [ -e "$source_root/output/registry/signup-tasks.sqlite" ] || [ -L "$source_root/output/registry/signup-tasks.sqlite" ]; }
  then
    src_rel_path="output/registry/signup-tasks.sqlite"
    src_path="$source_root/$src_rel_path"
  fi

  if [ ! -e "$src_path" ] && [ ! -L "$src_path" ]; then
    log "skip source missing: $rel_path"
    return 0
  fi

  if [ -e "$dst_path" ] || [ -L "$dst_path" ]; then
    log "keep target exists: $rel_path"
    return 0
  fi

  if [ "$DRY_RUN" = "1" ]; then
    if [ "${rel_path##*.}" = "sqlite" ]; then
      log "would snapshot: $rel_path"
    else
      log "would copy: $rel_path"
    fi
    return 0
  fi

  mkdir -p "$(dirname -- "$dst_path")"
  if [ "${rel_path##*.}" = "sqlite" ]; then
    tmp_path="${dst_path}.tmp.$$"
    if ! snapshot_sqlite "$src_path" "$tmp_path"; then
      rm -f "$tmp_path"
      return 1
    fi
    mv "$tmp_path" "$dst_path"
    log "snapshotted sqlite: $rel_path"
  else
    cp -R "$src_path" "$dst_path"
    log "copied: $rel_path"
  fi
}

extract_env_value() {
  env_file=$1
  key=$2
  [ -f "$env_file" ] || return 1
  raw_value=$(
    awk -v key="$key" '
      {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        if (line ~ /^#/ || line == "") next
        if (index(line, key "=") == 1) {
          value = substr(line, length(key) + 2)
        }
      }
      END {
        if (value == "") exit 1
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        print value
      }
    ' "$env_file"
  ) || return 1
  case "$raw_value" in
    \"*\")
      raw_value=${raw_value#\"}
      raw_value=${raw_value%\"}
      ;;
    \'*\')
      raw_value=${raw_value#\'}
      raw_value=${raw_value%\'}
      ;;
  esac
  printf '%s\n' "$raw_value"
}

resolve_browser_runtime_root() {
  executable_path=$1
  case "$executable_path" in
    */Chromium.app/Contents/MacOS/Chromium)
      printf '%s\n' "${executable_path%/Contents/MacOS/Chromium}"
      return 0
      ;;
    */fingerprint-browser/linux/chrome)
      printf '%s\n' "${executable_path%/chrome}"
      return 0
      ;;
    */fingerprint-browser/linux/*/chrome)
      dirname -- "$(dirname -- "$executable_path")"
      return 0
      ;;
  esac
  return 1
}

resolve_browser_install_dest() {
  browser_root=$1
  case "$browser_root" in
    */Chromium.app)
      dirname -- "$browser_root"
      ;;
    *)
      printf '%s\n' "$browser_root"
      ;;
  esac
}

bootstrap_browser_runtime() {
  env_path="$current_root/.env.local"
  chrome_path=$(extract_env_value "$env_path" "CHROME_EXECUTABLE_PATH" || true)
  if [ -z "$chrome_path" ]; then
    log "skip browser bootstrap: CHROME_EXECUTABLE_PATH unset"
    return 0
  fi

  case "$chrome_path" in
    /*)
      case "$chrome_path" in
        "$source_root"/*)
          rel_path=${chrome_path#"$source_root"/}
          src_executable="$chrome_path"
          dst_executable="$current_root/$rel_path"
          ;;
        "$current_root"/*)
          rel_path=${chrome_path#"$current_root"/}
          src_executable="$source_root/$rel_path"
          dst_executable="$chrome_path"
          ;;
        *)
          log "skip browser bootstrap: CHROME_EXECUTABLE_PATH external"
          return 0
          ;;
      esac
      ;;
    *)
      rel_path="$chrome_path"
      src_executable="$source_root/$rel_path"
      dst_executable="$current_root/$rel_path"
      ;;
  esac

  if [ -x "$dst_executable" ]; then
    log "keep browser runtime exists: $chrome_path"
    return 0
  fi

  src_browser_root=$(resolve_browser_runtime_root "$src_executable" || true)
  dst_browser_root=$(resolve_browser_runtime_root "$dst_executable" || true)
  if [ -z "$dst_browser_root" ]; then
    log "skip browser bootstrap: unsupported CHROME_EXECUTABLE_PATH"
    return 0
  fi

  if [ -e "$src_browser_root" ] || [ -L "$src_browser_root" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      log "would copy browser runtime: $chrome_path"
      return 0
    fi
    mkdir -p "$(dirname -- "$dst_browser_root")"
    rm -rf "$dst_browser_root"
    cp -R "$src_browser_root" "$dst_browser_root"
    log "copied browser runtime: $chrome_path"
    return 0
  fi

  installer_path="$current_root/scripts/install-fingerprint-browser.sh"
  manifest_path="$current_root/scripts/fingerprint-browser-manifest.json"
  if [ ! -x "$installer_path" ] || [ ! -f "$manifest_path" ]; then
    log "skip browser bootstrap: installer unavailable"
    return 0
  fi

  install_dest=$(resolve_browser_install_dest "$dst_browser_root")
  if [ "$DRY_RUN" = "1" ]; then
    log "would install browser runtime: $chrome_path"
    return 0
  fi

  log "installing browser runtime: $chrome_path"
  if ! "$installer_path" --platform auto --dest "$install_dest" --cache-dir "$current_root/downloads/fingerprint-browser" --force >/dev/null 2>&1; then
    log "skip browser bootstrap failed: $chrome_path"
    return 0
  fi
  log "installed browser runtime: $chrome_path"
}

current_root=$(canonical_dir "$(git rev-parse --show-toplevel)")
git_dir=$(resolve_git_path --git-dir)
common_dir=$(resolve_git_path --git-common-dir)

if [ "$git_dir" = "$common_dir" ]; then
  log "skip main worktree"
  exit 0
fi

if [ ! -f "$MANIFEST_PATH" ]; then
  log "skip manifest missing: $MANIFEST_PATH"
  exit 0
fi

old_head=${1:-manual}
new_head=${2:-manual}
is_branch_checkout=${3:-0}

if [ "$FORCE_SYNC" != "1" ]; then
  if [ "$old_head" != "$ZERO_OID" ] || [ "$is_branch_checkout" != "1" ]; then
    log "skip non-initial checkout"
    exit 0
  fi
fi

source_root=$(discover_main_root "$current_root" || true)
if [ -z "$source_root" ]; then
  log "skip source root unresolved"
  exit 0
fi

while IFS= read -r entry || [ -n "$entry" ]; do
  case "$entry" in
    ''|'#'*)
      continue
      ;;
  esac
  copy_resource "$entry"
done < "$MANIFEST_PATH"

bootstrap_browser_runtime
bootstrap_dependencies

if [ "$DRY_RUN" = "1" ]; then
  log "dry-run complete"
else
  log "sync complete"
fi
