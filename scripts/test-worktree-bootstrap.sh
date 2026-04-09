#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
repo_root="$(cd "$repo_root" && pwd -P)"

if ! command -v bun >/dev/null 2>&1; then
  echo "bun is required for worktree bootstrap smoke tests" >&2
  exit 1
fi
bun_bin="$(command -v bun)"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/tavreg-hikari-worktree-test.XXXXXX")"
tmp_root="$(cd "$tmp_root" && pwd -P)"
fixture_repo="$tmp_root/fixture-repo"
worktree_default="$tmp_root/default-worktree"
worktree_missing="$tmp_root/missing-source-worktree"
worktree_absolute="$tmp_root/absolute-browser-worktree"
worktree_cross_platform="$tmp_root/cross-platform-browser-worktree"
worktree_versioned="$tmp_root/versioned-browser-worktree"
legacy_hook_marker="$tmp_root/legacy-post-checkout.log"

cleanup() {
  set +e
  git -C "$fixture_repo" worktree remove -f "$worktree_default" >/dev/null 2>&1
  git -C "$fixture_repo" worktree remove -f "$worktree_missing" >/dev/null 2>&1
  git -C "$fixture_repo" worktree remove -f "$worktree_absolute" >/dev/null 2>&1
  git -C "$fixture_repo" worktree remove -f "$worktree_cross_platform" >/dev/null 2>&1
  git -C "$fixture_repo" worktree remove -f "$worktree_versioned" >/dev/null 2>&1
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

sha256_file() {
  local path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return 0
  fi
  echo "missing sha256 tool" >&2
  exit 1
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
cp "$repo_root/scripts/sqlite-snapshot.sh" "$fixture_repo/scripts/sqlite-snapshot.sh"
cp "$repo_root/scripts/sync-worktree-resources.sh" "$fixture_repo/scripts/sync-worktree-resources.sh"
cp "$repo_root/scripts/worktree-sync.paths" "$fixture_repo/scripts/worktree-sync.paths"
cp "$repo_root/scripts/install-fingerprint-browser.sh" "$fixture_repo/scripts/install-fingerprint-browser.sh"
cp "$repo_root/scripts/fingerprint-browser-manifest.json" "$fixture_repo/scripts/fingerprint-browser-manifest.json"
chmod +x   "$fixture_repo/scripts/install-hooks.sh"   "$fixture_repo/scripts/sqlite-snapshot.sh"   "$fixture_repo/scripts/sync-worktree-resources.sh"   "$fixture_repo/scripts/install-fingerprint-browser.sh"
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

mkdir -p "$fixture_repo/.tools/fingerprint-browser/linux/144.0.7559.132"
cat > "$fixture_repo/.tools/fingerprint-browser/linux/144.0.7559.132/chrome" <<'CHROME'
#!/bin/sh
exit 0
CHROME
chmod +x "$fixture_repo/.tools/fingerprint-browser/linux/144.0.7559.132/chrome"
ln -sfn 144.0.7559.132/chrome "$fixture_repo/.tools/fingerprint-browser/linux/chrome"
browser_binary_sha="$(sha256_file "$fixture_repo/.tools/fingerprint-browser/linux/144.0.7559.132/chrome")"
cat > "$fixture_repo/.tools/fingerprint-browser/linux/.fingerprint-browser-install.json" <<MARKER
{
  "schemaVersion": 1,
  "installer": "install-fingerprint-browser.sh",
  "platform": "linux",
  "version": "144.0.7559.132",
  "binaryRelativePath": "chrome",
  "binarySha256": "$browser_binary_sha"
}
MARKER
cat > "$fixture_repo/.tools/fingerprint-browser/linux/144.0.7559.132/.fingerprint-browser-install.json" <<MARKER
{
  "schemaVersion": 1,
  "installer": "install-fingerprint-browser.sh",
  "platform": "linux",
  "version": "144.0.7559.132",
  "binaryRelativePath": "chrome",
  "binarySha256": "$browser_binary_sha"
}
MARKER
mkdir -p "$fixture_repo/.tools/Chromium.app/Contents/MacOS"
cat > "$fixture_repo/.tools/Chromium.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Chromium</string>
  <key>CFBundleShortVersionString</key>
  <string>142.0.7444.175</string>
</dict>
</plist>
PLIST
cat > "$fixture_repo/.tools/Chromium.app/Contents/MacOS/Chromium" <<'CHROME'
#!/bin/sh
exit 0
CHROME
chmod +x "$fixture_repo/.tools/Chromium.app/Contents/MacOS/Chromium"
mac_browser_binary_sha="$(sha256_file "$fixture_repo/.tools/Chromium.app/Contents/MacOS/Chromium")"
cat > "$fixture_repo/.tools/.fingerprint-browser-install.json" <<MARKER
{
  "schemaVersion": 1,
  "installer": "install-fingerprint-browser.sh",
  "platform": "macos",
  "version": "142.0.7444.175",
  "binaryRelativePath": "Chromium.app/Contents/MacOS/Chromium",
  "binarySha256": "$mac_browser_binary_sha"
}
MARKER
browser_fixture_root="$tmp_root/browser-fixture"
mkdir -p "$browser_fixture_root/ungoogled-chromium-144.0.7559.132-1-x86_64_linux"
cat > "$browser_fixture_root/ungoogled-chromium-144.0.7559.132-1-x86_64_linux/chrome" <<'CHROME'
#!/bin/sh
exit 0
CHROME
chmod +x "$browser_fixture_root/ungoogled-chromium-144.0.7559.132-1-x86_64_linux/chrome"
browser_archive="$browser_fixture_root/ungoogled-chromium-144.0.7559.132-1-x86_64_linux.tar.xz"
tar -cJf "$browser_archive" -C "$browser_fixture_root" ungoogled-chromium-144.0.7559.132-1-x86_64_linux
browser_archive_sha="$(sha256_file "$browser_archive")"
mkdir -p "$browser_fixture_root/ungoogled-chromium-143.0.7000.0-1-x86_64_linux"
cat > "$browser_fixture_root/ungoogled-chromium-143.0.7000.0-1-x86_64_linux/chrome" <<'CHROME'
#!/bin/sh
exit 0
CHROME
chmod +x "$browser_fixture_root/ungoogled-chromium-143.0.7000.0-1-x86_64_linux/chrome"
legacy_browser_archive="$browser_fixture_root/ungoogled-chromium-143.0.7000.0-1-x86_64_linux.tar.xz"
tar -cJf "$legacy_browser_archive" -C "$browser_fixture_root" ungoogled-chromium-143.0.7000.0-1-x86_64_linux
legacy_browser_archive_sha="$(sha256_file "$legacy_browser_archive")"
browser_macos_bundle_root="$browser_fixture_root/macos-src"
mkdir -p "$browser_macos_bundle_root/Chromium.app/Contents/MacOS"
cp "$fixture_repo/.tools/Chromium.app/Contents/Info.plist" "$browser_macos_bundle_root/Chromium.app/Contents/Info.plist"
cp "$fixture_repo/.tools/Chromium.app/Contents/MacOS/Chromium" "$browser_macos_bundle_root/Chromium.app/Contents/MacOS/Chromium"
chmod +x "$browser_macos_bundle_root/Chromium.app/Contents/MacOS/Chromium"
browser_macos_archive="$browser_fixture_root/ungoogled-chromium_142.0.7444.175-1.1_macos.dmg"
if command -v hdiutil >/dev/null 2>&1; then
  hdiutil create -volname Chromium -srcfolder "$browser_macos_bundle_root" -format UDZO "$browser_macos_archive" >/dev/null
else
  printf 'placeholder dmg for non-darwin bootstrap fixtures\n' > "$browser_macos_archive"
fi
browser_macos_archive_sha="$(sha256_file "$browser_macos_archive")"
cat > "$fixture_repo/scripts/fingerprint-browser-manifest.json" <<MANIFEST
{
  "schemaVersion": 1,
  "defaultVersions": {
    "linux": "144.0.7559.132",
    "macos": "142.0.7444.175"
  },
  "releases": {
    "linux": {
      "143.0.7000.0": {
        "asset": "ungoogled-chromium-143.0.7000.0-1-x86_64_linux.tar.xz",
        "downloadUrl": "file://$legacy_browser_archive",
        "sha256": "$legacy_browser_archive_sha",
        "archiveType": "tar.xz",
        "binaryRelativePath": "chrome",
        "arch": "x86_64"
      },
      "144.0.7559.132": {
        "asset": "ungoogled-chromium-144.0.7559.132-1-x86_64_linux.tar.xz",
        "downloadUrl": "file://$browser_archive",
        "sha256": "$browser_archive_sha",
        "archiveType": "tar.xz",
        "binaryRelativePath": "chrome",
        "arch": "x86_64"
      }
    },
    "macos": {
      "142.0.7444.175": {
        "asset": "ungoogled-chromium_142.0.7444.175-1.1_macos.dmg",
        "downloadUrl": "file://$browser_macos_archive",
        "sha256": "$browser_macos_archive_sha",
        "archiveType": "dmg",
        "bundleName": "Chromium.app",
        "binaryRelativePath": "Contents/MacOS/Chromium"
      }
    }
  }
}
MANIFEST
git -C "$fixture_repo" add scripts/fingerprint-browser-manifest.json
git -C "$fixture_repo" commit -m 'test: use local fingerprint browser fixture' >/dev/null
head_sha="$(git -C "$fixture_repo" rev-parse HEAD)"
case "$(uname -s)" in
  Darwin)
    foreign_browser_path=".tools/fingerprint-browser/linux/chrome"
    expected_host_browser_path=".tools/Chromium.app/Contents/MacOS/Chromium"
    ;;
  Linux)
    foreign_browser_path=".tools/Chromium.app/Contents/MacOS/Chromium"
    expected_host_browser_path=".tools/fingerprint-browser/linux/chrome"
    ;;
  *)
    echo "unsupported host OS for worktree browser smoke" >&2
    exit 1
    ;;
esac
cat > "$fixture_repo/.env.local" <<'ENVLOCAL'
SOURCE_ENV=main-root
CHROME_EXECUTABLE_PATH=.tools/fingerprint-browser/linux/chrome
ENVLOCAL
sqlite_insert_value "$fixture_repo/output/registry/signup-tasks.sqlite" "main-ledger"
assert_exists "$fixture_repo/output/registry/signup-tasks.sqlite-shm"
assert_exists "$fixture_repo/output/registry/signup-tasks.sqlite-wal"

git -C "$fixture_repo" worktree add --detach "$worktree_default" HEAD >/dev/null
assert_file_content "$legacy_hook_marker" "legacy-hook-preserved"
assert_file_content "$worktree_default/.env.local" $'SOURCE_ENV=main-root
CHROME_EXECUTABLE_PATH='"$expected_host_browser_path"
assert_exists "$worktree_default/$expected_host_browser_path"
if [[ "$expected_host_browser_path" = ".tools/Chromium.app/Contents/MacOS/Chromium" ]]; then
  assert_exists "$worktree_default/.tools/.fingerprint-browser-install.json"
  "$fixture_repo/scripts/install-fingerprint-browser.sh" --platform macos --dest "$worktree_default/.tools" --cache-dir "$worktree_default/downloads/fingerprint-browser" --verify-only >/dev/null
fi
assert_exists "$worktree_default/node_modules"
if [[ -e "$worktree_default/bun.lock" ]]; then
  echo "expected bootstrap install without source bun.lock to avoid creating a lockfile" >&2
  exit 1
fi
assert_exists "$worktree_default/output/registry/tavreg-hikari.sqlite"
if [[ -e "$worktree_default/output/registry/tavreg-hikari.sqlite-shm" ]]; then
  echo "expected bootstrapped worktree SQLite snapshot to omit shm companion file" >&2
  exit 1
fi
if [[ -e "$worktree_default/output/registry/tavreg-hikari.sqlite-wal" ]]; then
  echo "expected bootstrapped worktree SQLite snapshot to omit wal companion file" >&2
  exit 1
fi
if [[ "$(sqlite_latest_value "$worktree_default/output/registry/tavreg-hikari.sqlite")" != "main-ledger" ]]; then
  echo "expected copied SQLite ledger to contain source fixture data" >&2
  exit 1
fi

cat > "$fixture_repo/.env.local" <<ENVLOCAL
SOURCE_ENV=absolute-runtime
CHROME_EXECUTABLE_PATH=$fixture_repo/.tools/fingerprint-browser/linux/chrome
ENVLOCAL
absolute_output="$(git -C "$fixture_repo" worktree add --detach "$worktree_absolute" HEAD 2>&1)"
assert_output_contains "$absolute_output" "rewrote browser path: $worktree_absolute/$expected_host_browser_path"
assert_file_content "$worktree_absolute/.env.local" $'SOURCE_ENV=absolute-runtime
CHROME_EXECUTABLE_PATH='"$worktree_absolute/$expected_host_browser_path"
assert_exists "$worktree_absolute/$expected_host_browser_path"

cat > "$fixture_repo/.env.local" <<'ENVLOCAL'
SOURCE_ENV=main-root
CHROME_EXECUTABLE_PATH=.tools/fingerprint-browser/linux/chrome
ENVLOCAL

cat > "$fixture_repo/.env.local" <<ENVLOCAL
SOURCE_ENV=cross-platform-runtime
CHROME_EXECUTABLE_PATH=$foreign_browser_path
ENVLOCAL
cross_platform_output="$(git -C "$fixture_repo" worktree add --detach "$worktree_cross_platform" HEAD 2>&1)"
assert_file_content "$worktree_cross_platform/.env.local" $'SOURCE_ENV=cross-platform-runtime
CHROME_EXECUTABLE_PATH='"$expected_host_browser_path"
assert_exists "$worktree_cross_platform/$expected_host_browser_path"

tampered_browser_path="$(python3 - <<'PY' "$worktree_cross_platform/$expected_host_browser_path"
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)"
cat > "$tampered_browser_path" <<'CHROME'
#!/bin/sh
exit 99
CHROME
chmod +x "$tampered_browser_path"
browser_repair_output="$(cd "$worktree_cross_platform" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$browser_repair_output" "repairing invalid browser runtime: $expected_host_browser_path"
assert_output_contains "$browser_repair_output" "copied browser runtime: $expected_host_browser_path"
assert_output_not_contains "$browser_repair_output" "keep browser runtime exists: $expected_host_browser_path"
assert_file_content "$tampered_browser_path" $'#!/bin/sh
exit 0'
if [[ "$expected_host_browser_path" = ".tools/Chromium.app/Contents/MacOS/Chromium" ]]; then
  assert_exists "$worktree_cross_platform/.tools/.fingerprint-browser-install.json"
  "$fixture_repo/scripts/install-fingerprint-browser.sh" --platform macos --dest "$worktree_cross_platform/.tools" --cache-dir "$worktree_cross_platform/downloads/fingerprint-browser" --verify-only >/dev/null
fi

cat > "$fixture_repo/.env.local" <<'ENVLOCAL'
SOURCE_ENV=main-root
CHROME_EXECUTABLE_PATH=.tools/fingerprint-browser/linux/chrome
ENVLOCAL

cat > "$worktree_default/.env.local" <<'ENVLOCAL'
SOURCE_ENV=worktree-custom
ENVLOCAL
sqlite_insert_value "$worktree_default/output/registry/tavreg-hikari.sqlite" "worktree-ledger"
preserve_output="$(cd "$worktree_default" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$preserve_output" "keep target exists: .env.local"
assert_output_contains "$preserve_output" "keep target exists: output/registry/tavreg-hikari.sqlite"
assert_file_content "$worktree_default/.env.local" "SOURCE_ENV=worktree-custom"
if [[ "$(sqlite_latest_value "$worktree_default/output/registry/tavreg-hikari.sqlite")" != "worktree-ledger" ]]; then
  echo "forced sync should not overwrite existing SQLite ledger" >&2
  exit 1
fi

main_output="$(cd "$fixture_repo" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$main_output" "skip main worktree"

rm -rf "$fixture_repo/.tools/fingerprint-browser/linux"
rm -f "$fixture_repo/output/registry/signup-tasks.sqlite"
missing_output="$(git -C "$fixture_repo" worktree add --detach "$worktree_missing" HEAD 2>&1)"
assert_output_contains "$missing_output" "skip source missing: output/registry/tavreg-hikari.sqlite"
assert_file_content "$worktree_missing/.env.local" $'SOURCE_ENV=main-root
CHROME_EXECUTABLE_PATH='"$expected_host_browser_path"
assert_exists "$worktree_missing/$expected_host_browser_path"
if [[ -e "$worktree_missing/output/registry/tavreg-hikari.sqlite" ]]; then
  echo "expected missing source SQLite file to stay absent in target worktree" >&2
  exit 1
fi

if [[ "$(uname -s)" = "Linux" ]]; then
  cat > "$fixture_repo/.env.local" <<'ENVLOCAL'
SOURCE_ENV=versioned-runtime
CHROME_EXECUTABLE_PATH=.tools/fingerprint-browser/linux/143.0.7000.0/chrome
ENVLOCAL
  rm -rf "$fixture_repo/.tools/fingerprint-browser/linux"
  versioned_output="$(git -C "$fixture_repo" worktree add --detach "$worktree_versioned" HEAD 2>&1)"
  assert_output_contains "$versioned_output" "installed browser runtime: .tools/fingerprint-browser/linux/143.0.7000.0/chrome"
  assert_file_content "$worktree_versioned/.env.local" $'SOURCE_ENV=versioned-runtime
CHROME_EXECUTABLE_PATH=.tools/fingerprint-browser/linux/143.0.7000.0/chrome'
  assert_exists "$worktree_versioned/.tools/fingerprint-browser/linux/143.0.7000.0/chrome"
fi

sqlite_insert_value "$fixture_repo/output/registry/signup-tasks.sqlite" "restored-ledger"
rm -f "$worktree_missing/output/registry/tavreg-hikari.sqlite"
sqlite_hold_writer "$fixture_repo/output/registry/signup-tasks.sqlite" "live-ledger"
writer_pid="$SQLITE_WRITER_PID"
sleep 1
live_sync_output="$(cd "$worktree_missing" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
wait "$writer_pid"
assert_output_contains "$live_sync_output" "snapshotted sqlite: output/registry/tavreg-hikari.sqlite"
if [[ "$(sqlite_latest_value "$worktree_missing/output/registry/tavreg-hikari.sqlite")" != "live-ledger" ]]; then
  echo "expected forced sync to snapshot a live SQLite source without losing committed rows" >&2
  exit 1
fi

fallback_bin="$tmp_root/fallback-bin"
mkdir -p "$fallback_bin"
cat > "$fallback_bin/sqlite3" <<'EOF'
#!/bin/sh
echo "Error: near \"INTO\": syntax error" >&2
exit 1
EOF
chmod +x "$fallback_bin/sqlite3"
rm -f "$worktree_missing/output/registry/tavreg-hikari.sqlite"
fallback_sync_output="$(cd "$worktree_missing" && PATH="$fallback_bin:$PATH" WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$fallback_sync_output" "snapshotted sqlite: output/registry/tavreg-hikari.sqlite"
if [[ "$(sqlite_latest_value "$worktree_missing/output/registry/tavreg-hikari.sqlite")" != "live-ledger" ]]; then
  echo "expected SQLite snapshot to fall back when sqlite3 lacks VACUUM INTO" >&2
  exit 1
fi

deps_output="$(cd "$worktree_default" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$deps_output" "keep dependency install: node_modules exists"
assert_output_not_contains "$deps_output" "installing dependencies:"

failure_bin="$tmp_root/failure-bin"
mkdir -p "$failure_bin"
cat > "$failure_bin/bun" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "install" ]; then
  mkdir -p node_modules
  echo "simulated bun install failure" >&2
  exit 7
fi
exec "__REAL_BUN__" "$@"
EOF
perl -0pi -e "s|__REAL_BUN__|$bun_bin|g" "$failure_bin/bun"
chmod +x "$failure_bin/bun"
rm -rf "$worktree_missing/node_modules"
install_failure_output="$(cd "$worktree_missing" && PATH="$failure_bin:$PATH" WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$install_failure_output" "skip dependency install failed:"
assert_exists "$worktree_missing/node_modules"
retry_install_output="$(cd "$worktree_missing" && WORKTREE_SYNC_FORCE=1 "$fixture_repo/scripts/sync-worktree-resources.sh" 2>&1)"
assert_output_contains "$retry_install_output" "installing dependencies: bun install --no-save"
assert_output_contains "$retry_install_output" "installed dependencies"

checkout_output="$(git -C "$fixture_repo" checkout "$base_sha" 2>&1)"
assert_output_not_contains "$checkout_output" "No such file or directory"
assert_output_not_contains "$checkout_output" "exit status 127"

checkout_output="$(git -C "$fixture_repo" checkout "$head_sha" 2>&1)"
assert_output_not_contains "$checkout_output" "No such file or directory"
assert_output_not_contains "$checkout_output" "exit status 127"

echo "worktree bootstrap smoke test passed"
