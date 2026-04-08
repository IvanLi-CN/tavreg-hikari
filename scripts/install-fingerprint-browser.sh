#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
MANIFEST_PATH=${FINGERPRINT_BROWSER_MANIFEST_PATH:-$SCRIPT_DIR/fingerprint-browser-manifest.json}

PLATFORM="auto"
VERSION=""
DEST=""
CACHE_DIR=""
FORCE=0
VERIFY_ONLY=0

usage() {
  cat <<'USAGE'
Usage: ./scripts/install-fingerprint-browser.sh [options]

Options:
  --platform auto|linux|macos
  --version <supported-version>
  --dest <absolute-or-repo-relative-install-root>
  --cache-dir <download-cache-dir>
  --force
  --verify-only
USAGE
}

log() {
  printf 'fingerprint-browser-install: %s\n' "$*"
}

fail() {
  printf 'fingerprint-browser-install: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

resolve_path() {
  node --input-type=module -e 'import path from "node:path"; console.log(path.resolve(process.argv[1], process.argv[2]));' "$REPO_ROOT" "$1"
}

parse_manifest_entry() {
  node --input-type=module - "$MANIFEST_PATH" "$PLATFORM" "$VERSION" <<'NODE'
import fs from "node:fs";

const [manifestPath, platform, requestedVersion] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
if (manifest.schemaVersion !== 1) {
  throw new Error(`Unsupported manifest schema: ${manifest.schemaVersion}`);
}
const defaults = manifest.defaultVersions || {};
const releaseMap = manifest.releases?.[platform] || null;
if (!releaseMap || typeof releaseMap !== "object") {
  throw new Error(`Unsupported platform: ${platform}`);
}
const version = requestedVersion || defaults[platform];
if (!version || !releaseMap[version]) {
  const supported = Object.keys(releaseMap).sort().join(", ");
  throw new Error(`Unsupported version for ${platform}: ${requestedVersion || "<default>"}. Supported: ${supported}`);
}
const entry = releaseMap[version];
const requiredFields = ["asset", "downloadUrl", "sha256", "archiveType", "binaryRelativePath"];
for (const field of requiredFields) {
  if (typeof entry[field] !== "string" || entry[field].trim() === "") {
    throw new Error(`Manifest entry for ${platform}@${version} is missing ${field}`);
  }
}
if (platform === "linux" && entry.archiveType !== "tar.xz") {
  throw new Error(`Manifest entry for ${platform}@${version} must use archiveType tar.xz`);
}
if (platform === "macos") {
  if (entry.archiveType !== "dmg") {
    throw new Error(`Manifest entry for ${platform}@${version} must use archiveType dmg`);
  }
  if (typeof entry.bundleName !== "string" || entry.bundleName.trim() === "") {
    throw new Error(`Manifest entry for ${platform}@${version} is missing bundleName`);
  }
}
const fields = {
  resolved_version: version,
  asset_name: entry.asset,
  download_url: entry.downloadUrl,
  sha256: entry.sha256,
  archive_type: entry.archiveType,
  binary_relative_path: entry.binaryRelativePath || "",
  bundle_name: entry.bundleName || ""
};
for (const [key, value] of Object.entries(fields)) {
  const scalar = String(value || "");
  const escaped = `'${scalar.replaceAll("'", `'\\''`)}'`;
  console.log(`${key}=${escaped}`);
}
NODE
}

compute_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return 0
  fi
  fail "missing sha256 tool (shasum/sha256sum)"
}

verify_checksum() {
  local file_path=$1
  local expected=$2
  local actual
  actual=$(compute_sha256 "$file_path")
  if [ "$actual" != "$expected" ]; then
    fail "checksum mismatch for $(basename "$file_path"): expected $expected, got $actual"
  fi
}

ensure_downloaded() {
  local url=$1
  local archive_path=$2
  local expected=$3
  mkdir -p "$(dirname "$archive_path")"
  if [ -f "$archive_path" ]; then
    local cached
    cached=$(compute_sha256 "$archive_path")
    if [ "$cached" = "$expected" ]; then
      log "reuse cached asset $(basename "$archive_path")"
      return 0
    fi
    rm -f "$archive_path"
  fi
  need_cmd curl
  log "downloading $(basename "$archive_path")"
  curl -L --fail --retry 3 --retry-all-errors --silent --show-error -o "$archive_path" "$url"
  verify_checksum "$archive_path" "$expected"
}

read_macos_bundle_version() {
  local bundle_path=$1
  local plist_path="$bundle_path/Contents/Info.plist"
  if [ ! -f "$plist_path" ]; then
    return 1
  fi
  /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist_path" 2>/dev/null || true
}

write_install_marker() {
  local marker_dir=$1
  local platform=$2
  local version=$3
  local binary_relative_path=$4
  local marker_path="$marker_dir/.fingerprint-browser-install.json"
  mkdir -p "$marker_dir"
  node --input-type=module - "$marker_path" "$platform" "$version" "$binary_relative_path" <<'NODE'
import fs from "node:fs";

const [markerPath, platform, version, binaryRelativePath] = process.argv.slice(2);
const marker = {
  schemaVersion: 1,
  installer: "install-fingerprint-browser.sh",
  platform,
  version,
  binaryRelativePath,
};
fs.writeFileSync(markerPath, JSON.stringify(marker, null, 2) + "\n", "utf8");
NODE
}

write_linux_install_markers() {
  local install_root=$1
  local version=$2
  local binary_relative_path=$3
  write_install_marker "$install_root" "linux" "$version" "$binary_relative_path"
  write_install_marker "$install_root/$version" "linux" "$version" "$binary_relative_path"
}

verify_linux_install() {
  local install_root=$1
  local version=$2
  local binary_relative_path=$3
  local version_dir="$install_root/$version"
  local executable_path="$version_dir/$binary_relative_path"
  local stable_path="$install_root/chrome"
  [ -x "$executable_path" ] || fail "linux fingerprint browser executable missing: $executable_path"
  [ -L "$stable_path" ] || fail "linux fingerprint browser symlink missing: $stable_path"
  local target
  target=$(readlink "$stable_path")
  [ "$target" = "$version/$binary_relative_path" ] || fail "linux fingerprint browser symlink drifted: $stable_path -> $target"
  printf '%s\n' "$stable_path"
}

install_linux_release() {
  local install_root=$1
  local archive_path=$2
  local version=$3
  local binary_relative_path=$4
  local version_dir="$install_root/$version"
  local stable_path="$install_root/chrome"
  if [ "$VERIFY_ONLY" = "1" ]; then
    verify_linux_install "$install_root" "$version" "$binary_relative_path"
    return 0
  fi
  if [ -x "$version_dir/$binary_relative_path" ] && [ "$FORCE" = "0" ]; then
    log "linux release $version already installed"
    write_linux_install_markers "$install_root" "$version" "$binary_relative_path"
    verify_linux_install "$install_root" "$version" "$binary_relative_path" >/dev/null
    printf '%s\n' "$stable_path"
    return 0
  fi
  local tmp_dir
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' RETURN
  rm -rf "$version_dir"
  mkdir -p "$install_root"
  tar -xJf "$archive_path" -C "$tmp_dir"
  local archive_root
  archive_root=$(tar -tf "$archive_path" | awk 'NR==1 {sub(/\/.*/, "", $0); print $0}')
  [ -n "$archive_root" ] || fail "unable to determine linux archive root"
  [ -d "$tmp_dir/$archive_root" ] || fail "linux archive root missing after extraction: $archive_root"
  mv "$tmp_dir/$archive_root" "$version_dir"
  [ -x "$version_dir/$binary_relative_path" ] || fail "linux fingerprint browser executable missing after extraction: $version_dir/$binary_relative_path"
  ln -sfn "$version/$binary_relative_path" "$stable_path"
  write_linux_install_markers "$install_root" "$version" "$binary_relative_path"
  verify_linux_install "$install_root" "$version" "$binary_relative_path"
  trap - RETURN
  rm -rf "$tmp_dir"
}

install_macos_release() {
  local install_root=$1
  local archive_path=$2
  local version=$3
  local bundle_name=$4
  local binary_relative_path=$5
  local bundle_path="$install_root/$bundle_name"
  local executable_path="$bundle_path/$binary_relative_path"
  if [ "$VERIFY_ONLY" = "1" ]; then
    [ -x "$executable_path" ] || fail "macOS fingerprint browser executable missing: $executable_path"
    local installed_version
    installed_version=$(read_macos_bundle_version "$bundle_path")
    [ "$installed_version" = "$version" ] || fail "macOS fingerprint browser version mismatch: expected $version, got ${installed_version:-<unknown>}"
    printf '%s\n' "$executable_path"
    return 0
  fi
  if [ -x "$executable_path" ] && [ "$FORCE" = "0" ]; then
    local installed_version
    installed_version=$(read_macos_bundle_version "$bundle_path")
    if [ "$installed_version" = "$version" ]; then
      log "macOS release $version already installed"
      printf '%s\n' "$executable_path"
      return 0
    fi
  fi
  need_cmd hdiutil
  need_cmd ditto
  need_cmd xattr
  local mount_point=""
  cleanup_mount() {
    if [ -n "$mount_point" ] && [ -d "$mount_point" ]; then
      hdiutil detach "$mount_point" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_mount RETURN
  rm -rf "$bundle_path"
  mkdir -p "$install_root"
  local attach_output
  attach_output=$(hdiutil attach -nobrowse -readonly "$archive_path")
  mount_point=$(printf '%s\n' "$attach_output" | awk 'END {print $NF}')
  [ -n "$mount_point" ] || fail "unable to determine macOS mount point"
  [ -d "$mount_point/$bundle_name" ] || fail "bundle missing from dmg: $bundle_name"
  ditto "$mount_point/$bundle_name" "$bundle_path"
  xattr -dr com.apple.quarantine "$bundle_path" >/dev/null 2>&1 || true
  [ -x "$executable_path" ] || fail "macOS fingerprint browser executable missing after copy: $executable_path"
  local installed_version
  installed_version=$(read_macos_bundle_version "$bundle_path")
  [ "$installed_version" = "$version" ] || fail "macOS fingerprint browser version mismatch after install: expected $version, got ${installed_version:-<unknown>}"
  printf '%s\n' "$executable_path"
  cleanup_mount
  trap - RETURN
}

while [ $# -gt 0 ]; do
  case "$1" in
    --platform)
      [ $# -ge 2 ] || fail "--platform requires a value"
      PLATFORM=$2
      shift 2
      ;;
    --version)
      [ $# -ge 2 ] || fail "--version requires a value"
      VERSION=$2
      shift 2
      ;;
    --dest)
      [ $# -ge 2 ] || fail "--dest requires a value"
      DEST=$2
      shift 2
      ;;
    --cache-dir)
      [ $# -ge 2 ] || fail "--cache-dir requires a value"
      CACHE_DIR=$2
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "$PLATFORM" in
  auto)
    case "$(uname -s)" in
      Linux) PLATFORM="linux" ;;
      Darwin) PLATFORM="macos" ;;
      *) fail "unsupported host platform: $(uname -s)" ;;
    esac
    ;;
  linux|macos) ;;
  *) fail "unsupported platform: $PLATFORM" ;;
esac

need_cmd node
[ -f "$MANIFEST_PATH" ] || fail "manifest not found: $MANIFEST_PATH"

eval "$(parse_manifest_entry)"

if [ -z "$DEST" ]; then
  case "$PLATFORM" in
    linux) DEST="$REPO_ROOT/.tools/fingerprint-browser/linux" ;;
    macos) DEST="$REPO_ROOT/.tools" ;;
  esac
fi
if [ -z "$CACHE_DIR" ]; then
  CACHE_DIR="$REPO_ROOT/downloads/fingerprint-browser"
fi

DEST=$(resolve_path "$DEST")
CACHE_DIR=$(resolve_path "$CACHE_DIR")
ARCHIVE_PATH="$CACHE_DIR/$asset_name"

if [ "$VERIFY_ONLY" = "0" ]; then
  ensure_downloaded "$download_url" "$ARCHIVE_PATH" "$sha256"
fi

case "$PLATFORM" in
  linux)
    install_linux_release "$DEST" "$ARCHIVE_PATH" "$resolved_version" "$binary_relative_path"
    ;;
  macos)
    install_macos_release "$DEST" "$ARCHIVE_PATH" "$resolved_version" "$bundle_name" "$binary_relative_path"
    ;;
esac
