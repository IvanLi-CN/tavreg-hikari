#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
repo_root="$(cd "$repo_root" && pwd -P)"

if ! command -v bun >/dev/null 2>&1; then
  echo "bun is required for worktree bootstrap smoke tests" >&2
  exit 1
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/tavreg-hikari-worktree-test.XXXXXX")"
tmp_root="$(cd "$tmp_root" && pwd -P)"
fixture_repo="$tmp_root/fixture-repo"
worktree_default="$tmp_root/default-worktree"
worktree_missing="$tmp_root/missing-source-worktree"
legacy_hook_marker="$tmp_root/legacy-post-checkout.log"

cleanup() {
  set +e
  git -C "$fixture_repo" worktree remove -f "$worktree_default" >/dev/null 2>&1
  git -C "$fixture_repo" worktree remove -f "$worktree_missing" >/dev/null 2>&1
  rm -rf "$tmp_root"
}
trap cleanup EXIT

assert_file_content() {
  local path="$1"
  local expected="$2"
  local actual

  if [[ ! -f "$path" ]]; then
    echo "expected file missing: $path" >&2
    exit 1
  fi

  actual="$(cat "$path")"
  if [[ "$actual" != "$expected" ]]; then
    echo "unexpected content for $path" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    exit 1
  fi
}

assert_exists() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "expected path missing: $path" >&2
    exit 1
  fi
}

assert_output_contains() {
  local output="$1"
  local needle="$2"
  if [[ "$output" != *"$needle"* ]]; then
    echo "expected output to contain '$needle'" >&2
    printf 'actual output:\n%s\n' "$output" >&2
    exit 1
  fi
}

assert_output_not_contains() {
  local output="$1"
  local needle="$2"
  if [[ "$output" == *"$needle"* ]]; then
    echo "expected output to omit '$needle'" >&2
    printf 'actual output:\n%s\n' "$output" >&2
    exit 1
  fi
}

sqlite_insert_value() {
  local db_path="$1"
  local value="$2"

  mkdir -p "$(dirname "$db_path")"
  bun --eval '
    import { Database } from "bun:sqlite";

    const dbPath = process.argv[1];
    const value = process.argv[2];
    const db = new Database(dbPath);
    db.exec("PRAGMA journal_mode=WAL;");
    db.exec("CREATE TABLE IF NOT EXISTS smoke (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL);");
    db.query("INSERT INTO smoke (value) VALUES (?)").run(value);
    db.close(false);
  ' "$db_path" "$value" >/dev/null
}

sqlite_latest_value() {
  local db_path="$1"

  bun --eval '
    import { Database } from "bun:sqlite";

    const dbPath = process.argv[1];
    const db = new Database(dbPath);
    const row = db.query("SELECT value FROM smoke ORDER BY id DESC LIMIT 1").get();
    console.log(row?.value ?? "");
    db.close(false);
  ' "$db_path"
}

sqlite_hold_writer() {
  local db_path="$1"
  local value="$2"
  local hold_ms="${3:-4000}"

  mkdir -p "$(dirname "$db_path")"
  bun --eval '
    import { Database } from "bun:sqlite";

    const dbPath = process.argv[1];
    const value = process.argv[2];
    const holdMs = Number(process.argv[3] ?? "4000");
    const db = new Database(dbPath);
    db.exec("PRAGMA journal_mode=WAL;");
    db.exec("CREATE TABLE IF NOT EXISTS smoke (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL);");
    db.query("INSERT INTO smoke (value) VALUES (?)").run(value);
    await Bun.sleep(holdMs);
    db.close(false);
  ' "$db_path" "$value" "$hold_ms" >/dev/null &
  SQLITE_WRITER_PID=$!
}

mkdir -p "$fixture_repo"
cat > "$fixture_repo/package.json" <<'JSON'
{
  "name": "tavreg-hikari-worktree-fixture",
  "private": true,
  "scripts": {
    "hooks:install": "sh ./scripts/install-hooks.sh",
    "prepare": "sh ./scripts/install-hooks.sh",
    "test:worktree-bootstrap": "bash ./scripts/test-worktree-bootstrap.sh"
  }
}
JSON

git -C "$fixture_repo" init -b main >/dev/null
git -C "$fixture_repo" config user.name 'Codex Test'
git -C "$fixture_repo" config user.email 'codex-test@example.com'
git -C "$fixture_repo" add package.json
git -C "$fixture_repo" commit -m 'test: base fixture without bootstrap scripts' >/dev/null
base_sha="$(git -C "$fixture_repo" rev-parse HEAD)"

mkdir -p "$fixture_repo/scripts"
cp "$repo_root/scripts/install-hooks.sh" "$fixture_repo/scripts/install-hooks.sh"
cp "$repo_root/scripts/sync-worktree-resources.sh" "$fixture_repo/scripts/sync-worktree-resources.sh"
cp "$repo_root/scripts/worktree-sync.paths" "$fixture_repo/scripts/worktree-sync.paths"
chmod +x \
  "$fixture_repo/scripts/install-hooks.sh" \
  "$fixture_repo/scripts/sync-worktree-resources.sh"
git -C "$fixture_repo" add scripts
git -C "$fixture_repo" commit -m 'test: add worktree bootstrap scripts' >/dev/null
head_sha="$(git -C "$fixture_repo" rev-parse HEAD)"

cat > "$fixture_repo/.git/hooks/post-checkout" <<HOOK
#!/bin/sh
printf 'legacy-hook-preserved\n' >> '$legacy_hook_marker'
HOOK
chmod +x "$fixture_repo/.git/hooks/post-checkout"

bun install --cwd "$fixture_repo" >/dev/null

recorded_main_root="$(git -C "$fixture_repo" config --local --get codex.worktree-sync.main-root || true)"
if [[ "$recorded_main_root" != "$fixture_repo" ]]; then
  echo "expected recorded main root to point at fixture repo" >&2
  exit 1
fi

cat > "$fixture_repo/.env.local" <<'ENVLOCAL'
SOURCE_ENV=main-root
ENVLOCAL
sqlite_insert_value "$fixture_repo/output/registry/signup-tasks.sqlite" "main-ledger"
assert_exists "$fixture_repo/output/registry/signup-tasks.sqlite-shm"
assert_exists "$fixture_repo/output/registry/signup-tasks.sqlite-wal"

git -C "$fixture_repo" worktree add --detach "$worktree_default" HEAD >/dev/null
assert_file_content "$legacy_hook_marker" "legacy-hook-preserved"
assert_file_content "$worktree_default/.env.local" "SOURCE_ENV=main-root"
assert_exists "$worktree_default/node_modules"
assert_exists "$worktree_default/output/registry/signup-tasks.sqlite"
if [[ -e "$worktree_default/output/registry/signup-tasks.sqlite-shm" ]]; then
  echo "expected bootstrapped worktree SQLite snapshot to omit shm companion file" >&2
  exit 1
fi
if [[ -e "$worktree_default/output/registry/signup-tasks.sqlite-wal" ]]; then
  echo "expected bootstrapped worktree SQLite snapshot to omit wal companion file" >&2
  exit 1
fi
if [[ "$(sqlite_latest_value "$worktree_default/output/registry/signup-tasks.sqlite")" != "main-ledger" ]]; then
  echo "expected copied SQLite ledger to contain source fixture data" >&2
  exit 1
fi

cat > "$worktree_default/.env.local" <<'ENVLOCAL'
SOURCE_ENV=worktree-custom
ENVLOCAL
sqlite_insert_value "$worktree_default/output/registry/signup-tasks.sqlite" "worktree-ledger"
preserve_output="$(cd "$worktree_default" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$preserve_output" "keep target exists: .env.local"
assert_output_contains "$preserve_output" "keep target exists: output/registry/signup-tasks.sqlite"
assert_file_content "$worktree_default/.env.local" "SOURCE_ENV=worktree-custom"
if [[ "$(sqlite_latest_value "$worktree_default/output/registry/signup-tasks.sqlite")" != "worktree-ledger" ]]; then
  echo "forced sync should not overwrite existing SQLite ledger" >&2
  exit 1
fi

main_output="$(cd "$fixture_repo" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$main_output" "skip main worktree"

rm -f "$fixture_repo/output/registry/signup-tasks.sqlite"
missing_output="$(git -C "$fixture_repo" worktree add --detach "$worktree_missing" HEAD 2>&1)"
assert_output_contains "$missing_output" "skip source missing: output/registry/signup-tasks.sqlite"
assert_file_content "$worktree_missing/.env.local" "SOURCE_ENV=main-root"
if [[ -e "$worktree_missing/output/registry/signup-tasks.sqlite" ]]; then
  echo "expected missing source SQLite file to stay absent in target worktree" >&2
  exit 1
fi

sqlite_insert_value "$fixture_repo/output/registry/signup-tasks.sqlite" "restored-ledger"
rm -f "$worktree_missing/output/registry/signup-tasks.sqlite"
sqlite_hold_writer "$fixture_repo/output/registry/signup-tasks.sqlite" "live-ledger"
writer_pid="$SQLITE_WRITER_PID"
sleep 1
live_sync_output="$(cd "$worktree_missing" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
wait "$writer_pid"
assert_output_contains "$live_sync_output" "snapshotted sqlite: output/registry/signup-tasks.sqlite"
if [[ "$(sqlite_latest_value "$worktree_missing/output/registry/signup-tasks.sqlite")" != "live-ledger" ]]; then
  echo "expected forced sync to snapshot a live SQLite source without losing committed rows" >&2
  exit 1
fi

checkout_output="$(git -C "$fixture_repo" checkout "$base_sha" 2>&1)"
assert_output_not_contains "$checkout_output" "No such file or directory"
assert_output_not_contains "$checkout_output" "exit status 127"

checkout_output="$(git -C "$fixture_repo" checkout "$head_sha" 2>&1)"
assert_output_not_contains "$checkout_output" "No such file or directory"
assert_output_not_contains "$checkout_output" "exit status 127"

echo "worktree bootstrap smoke test passed"
