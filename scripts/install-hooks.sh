#!/bin/sh
set -eu

MAIN_ROOT_KEY=codex.worktree-sync.main-root
MANAGED_MARKER="codex-worktree-sync managed post-checkout"
PREV_SUFFIX=".codex-worktree-sync-prev"

log() {
  printf 'hooks-install: %s\n' "$*"
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

write_managed_hook() {
  hook_path=$1
  prev_hook=$2
  escaped_prev_hook=$(printf '%s' "$prev_hook" | sed "s/'/'\\\\''/g")

  cat > "$hook_path" <<HOOK
#!/bin/sh
set -eu

# $MANAGED_MARKER
PREV_HOOK='$escaped_prev_hook'

if [ -x "\$PREV_HOOK" ]; then
  "\$PREV_HOOK" "\$@" || exit \$?
fi

repo_root=\$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "\$repo_root" ]; then
  exit 0
fi

sync_script="\$repo_root/scripts/sync-worktree-resources.sh"
if [ ! -x "\$sync_script" ]; then
  exit 0
fi

"\$sync_script" "\$@" || exit \$?
HOOK

  chmod +x "$hook_path"
}

current_root=$(canonical_dir "$(git rev-parse --show-toplevel)")
main_root=$(discover_main_root "$current_root" || true)
if [ -n "$main_root" ]; then
  git config --local "$MAIN_ROOT_KEY" "$main_root"
fi

hooks_dir=$(resolve_git_path --git-path hooks)
mkdir -p "$hooks_dir"

hook_path="$hooks_dir/post-checkout"
prev_hook="$hook_path$PREV_SUFFIX"

if [ -e "$hook_path" ] || [ -L "$hook_path" ]; then
  if grep -q "$MANAGED_MARKER" "$hook_path" 2>/dev/null; then
    log "refresh managed post-checkout"
  else
    cp "$hook_path" "$prev_hook"
    chmod +x "$prev_hook"
    log "preserved existing post-checkout hook"
  fi
fi

write_managed_hook "$hook_path" "$prev_hook"
log "installed post-checkout hook at $hook_path"
