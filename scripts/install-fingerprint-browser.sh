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

resolve_host_os() {
  printf '%s\n' "${FINGERPRINT_BROWSER_HOST_OS:-$(uname -s)}"
}

resolve_host_arch() {
  printf '%s\n' "${FINGERPRINT_BROWSER_HOST_ARCH:-$(uname -m)}"
}

normalize_linux_arch() {
  case "$1" in
    x86_64|amd64)
      printf '%s\n' "x86_64"
      ;;
    aarch64|arm64)
      printf '%s\n' "arm64"
      ;;
    *)
      printf '%s\n' "$1"
      ;;
  esac
}

assert_supported_linux_arch() {
  local asset_arch=$1
  local version=$2
  local host_os
  host_os=$(resolve_host_os)
  case "$host_os" in
    Linux|linux) ;;
    *) return 0 ;;
  esac
  local host_arch
  host_arch=$(normalize_linux_arch "$(resolve_host_arch)")
  local normalized_asset_arch
  normalized_asset_arch=$(normalize_linux_arch "$asset_arch")
  if [ "$host_arch" != "$normalized_asset_arch" ]; then
    fail "linux fingerprint browser ${version} supports only ${normalized_asset_arch}; current Linux arch is ${host_arch}"
  fi
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
if (platform === "linux") {
  if (entry.archiveType !== "tar.xz") {
    throw new Error(`Manifest entry for ${platform}@${version} must use archiveType tar.xz`);
  }
  if (typeof entry.arch !== "string" || entry.arch.trim() === "") {
    throw new Error(`Manifest entry for ${platform}@${version} is missing arch`);
  }
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
  asset_arch: entry.arch || "",
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
  local binary_sha256=${5:-}
  local marker_path="$marker_dir/.fingerprint-browser-install.json"
  mkdir -p "$marker_dir"
  node --input-type=module - "$marker_path" "$platform" "$version" "$binary_relative_path" "$binary_sha256" <<'NODE'
import fs from "node:fs";

const [markerPath, platform, version, binaryRelativePath, binarySha256] = process.argv.slice(2);
const marker = {
  schemaVersion: 1,
  installer: "install-fingerprint-browser.sh",
  platform,
  version,
  binaryRelativePath,
};
if (binarySha256) marker.binarySha256 = binarySha256;
fs.writeFileSync(markerPath, JSON.stringify(marker, null, 2) + "\n", "utf8");
NODE
}

write_linux_install_markers() {
  local install_root=$1
  local version=$2
  local binary_relative_path=$3
  local binary_sha256=$4
  write_install_marker "$install_root" "linux" "$version" "$binary_relative_path" "$binary_sha256"
  write_install_marker "$install_root/$version" "linux" "$version" "$binary_relative_path" "$binary_sha256"
}

read_linux_archive_root() {
  local archive_path=$1
  local archive_root
  archive_root=$(tar -tf "$archive_path" | awk 'NR==1 {sub(/\/.*/, "", $0); print $0}')
  [ -n "$archive_root" ] || fail "unable to determine linux archive root"
  printf '%s\n' "$archive_root"
}

read_linux_archive_binary_sha256() {
  local archive_path=$1
  local binary_relative_path=$2
  [ -f "$archive_path" ] || fail "linux archive missing: $archive_path"
  local tmp_dir
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' RETURN
  tar -xJf "$archive_path" -C "$tmp_dir"
  local archive_root
  archive_root=$(read_linux_archive_root "$archive_path")
  local extracted_binary="$tmp_dir/$archive_root/$binary_relative_path"
  [ -x "$extracted_binary" ] || fail "linux archive binary missing: $extracted_binary"
  compute_sha256 "$extracted_binary"
  trap - RETURN
  rm -rf "$tmp_dir"
}

read_install_binary_sha256() {
  local marker_dir=$1
  local marker_path="$marker_dir/.fingerprint-browser-install.json"
  [ -f "$marker_path" ] || fail "fingerprint browser marker missing: $marker_path"
  node --input-type=module - "$marker_path" <<'NODE'
import fs from "node:fs";

const [markerPath] = process.argv.slice(2);
const marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
if (typeof marker.binarySha256 !== "string" || marker.binarySha256.trim() === "") {
  throw new Error(`binarySha256 missing: ${markerPath}`);
}
console.log(marker.binarySha256);
NODE
}

read_install_marker_field() {
  local marker_dir=$1
  local field_name=$2
  local marker_path="$marker_dir/.fingerprint-browser-install.json"
  [ -f "$marker_path" ] || fail "fingerprint browser marker missing: $marker_path"
  node --input-type=module - "$marker_path" "$field_name" <<'NODE'
import fs from "node:fs";

const [markerPath, fieldName] = process.argv.slice(2);
const marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
const value = marker[fieldName];
if (typeof value !== "string" || value.trim() === "") {
  throw new Error(`${fieldName} missing: ${markerPath}`);
}
console.log(value);
NODE
}
verify_install_marker() {
  local marker_dir=$1
  local expected_platform=$2
  local expected_version=$3
  local expected_binary_relative_path=$4
  local expected_binary_path=$5
  local expected_binary_sha256=${6:-}
  local marker_path="$marker_dir/.fingerprint-browser-install.json"
  [ -f "$marker_path" ] || fail "fingerprint browser marker missing: $marker_path"
  node --input-type=module - "$marker_path" "$marker_dir" "$expected_platform" "$expected_version" "$expected_binary_relative_path" "$expected_binary_path" "$expected_binary_sha256" <<'NODE'
import fs from "node:fs";
import path from "node:path";

const [markerPath, markerDir, expectedPlatform, expectedVersion, expectedBinaryRelativePath, expectedBinaryPath, expectedBinarySha256] = process.argv.slice(2);
const marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
if (marker.schemaVersion !== 1) throw new Error(`schemaVersion mismatch: ${markerPath}`);
if (marker.installer !== "install-fingerprint-browser.sh") throw new Error(`installer mismatch: ${markerPath}`);
if (marker.platform !== expectedPlatform) throw new Error(`platform mismatch: ${markerPath}`);
if (marker.version !== expectedVersion) throw new Error(`version mismatch: ${markerPath}`);
if (marker.binaryRelativePath !== expectedBinaryRelativePath) throw new Error(`binaryRelativePath mismatch: ${markerPath}`);
const resolvedBinaryPath = path.resolve(markerDir, marker.binaryRelativePath);
if (resolvedBinaryPath !== path.resolve(expectedBinaryPath)) {
  throw new Error(`binary path mismatch: ${markerPath}`);
}
if (expectedBinarySha256 && marker.binarySha256 !== expectedBinarySha256) {
  throw new Error(`binarySha256 mismatch: ${markerPath}`);
}
NODE
}

verify_linux_install() {
  local install_root=$1
  local version=$2
  local binary_relative_path=$3
  local expected_binary_sha256=${4:-}
  local version_dir="$install_root/$version"
  local executable_path="$version_dir/$binary_relative_path"
  local stable_path="$install_root/chrome"
  local requested_target="$version/$binary_relative_path"
  local root_marker_path="$install_root/.fingerprint-browser-install.json"
  local root_marker_version=""
  local stable_target=""
  [ -x "$executable_path" ] || fail "linux fingerprint browser executable missing: $executable_path"
  if [ -z "$expected_binary_sha256" ]; then
    expected_binary_sha256=$(read_install_binary_sha256 "$version_dir")
  fi
  verify_install_marker "$version_dir" "linux" "$version" "$binary_relative_path" "$executable_path" "$expected_binary_sha256"
  local actual_binary_sha256
  actual_binary_sha256=$(compute_sha256 "$executable_path")
  [ "$actual_binary_sha256" = "$expected_binary_sha256" ] || fail "linux fingerprint browser executable drifted: $executable_path"
  if [ -f "$root_marker_path" ]; then
    root_marker_version=$(read_install_marker_field "$install_root" "version")
  fi
  if [ -L "$stable_path" ]; then
    stable_target=$(readlink "$stable_path")
  fi
  if [ "$root_marker_version" = "$version" ] || [ "$stable_target" = "$requested_target" ] || { [ ! -f "$root_marker_path" ] && [ ! -L "$stable_path" ]; }; then
    [ -L "$stable_path" ] || fail "linux fingerprint browser symlink missing: $stable_path"
    [ "$stable_target" = "$requested_target" ] || fail "linux fingerprint browser symlink drifted: $stable_path -> $stable_target"
    verify_install_marker "$install_root" "linux" "$version" "chrome" "$stable_path" "$expected_binary_sha256"
    printf '%s\n' "$stable_path"
    return 0
  fi
  printf '%s\n' "$executable_path"
}

verify_macos_install() {
  local install_root=$1
  local version=$2
  local bundle_name=$3
  local binary_relative_path=$4
  local expected_binary_sha256=${5:-}
  local bundle_path="$install_root/$bundle_name"
  local executable_path="$bundle_path/$binary_relative_path"
  [ -x "$executable_path" ] || fail "macOS fingerprint browser executable missing: $executable_path"
  local installed_version
  installed_version=$(read_macos_bundle_version "$bundle_path")
  [ "$installed_version" = "$version" ] || fail "macOS fingerprint browser version mismatch: expected $version, got ${installed_version:-<unknown>}"
  if [ -z "$expected_binary_sha256" ]; then
    expected_binary_sha256=$(read_install_binary_sha256 "$install_root")
  fi
  verify_install_marker "$install_root" "macos" "$version" "$bundle_name/$binary_relative_path" "$executable_path" "$expected_binary_sha256"
  local actual_binary_sha256
  actual_binary_sha256=$(compute_sha256 "$executable_path")
  [ "$actual_binary_sha256" = "$expected_binary_sha256" ] || fail "macOS fingerprint browser executable drifted: $executable_path"
  printf '%s\n' "$executable_path"
}

install_linux_release() {
  local install_root=$1
  local archive_path=$2
  local version=$3
  local binary_relative_path=$4
  local version_dir="$install_root/$version"
  local stable_path="$install_root/chrome"
  local expected_binary_sha256=""
  if [ "$VERIFY_ONLY" = "1" ]; then
    verify_linux_install "$install_root" "$version" "$binary_relative_path"
    return 0
  fi
  expected_binary_sha256=$(read_linux_archive_binary_sha256 "$archive_path" "$binary_relative_path")
  if [ -x "$version_dir/$binary_relative_path" ] && [ "$FORCE" = "0" ]; then
    local verified_path=""
    if verified_path=$(verify_linux_install "$install_root" "$version" "$binary_relative_path" "$expected_binary_sha256"); then
      log "linux release $version already installed"
      printf '%s\n' "$verified_path"
      return 0
    fi
    log "reinstalling invalid linux release $version"
  fi
  local tmp_dir
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' RETURN
  rm -rf "$version_dir"
  mkdir -p "$install_root"
  tar -xJf "$archive_path" -C "$tmp_dir"
  local archive_root
  archive_root=$(read_linux_archive_root "$archive_path")
  [ -d "$tmp_dir/$archive_root" ] || fail "linux archive root missing after extraction: $archive_root"
  mv "$tmp_dir/$archive_root" "$version_dir"
  [ -x "$version_dir/$binary_relative_path" ] || fail "linux fingerprint browser executable missing after extraction: $version_dir/$binary_relative_path"
  ln -sfn "$version/$binary_relative_path" "$stable_path"
  write_linux_install_markers "$install_root" "$version" "$binary_relative_path" "$expected_binary_sha256"
  verify_linux_install "$install_root" "$version" "$binary_relative_path" "$expected_binary_sha256"
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
    verify_macos_install "$install_root" "$version" "$bundle_name" "$binary_relative_path"
    return 0
  fi
  if [ -x "$executable_path" ] && [ "$FORCE" = "0" ]; then
    if ( verify_macos_install "$install_root" "$version" "$bundle_name" "$binary_relative_path" >/dev/null 2>&1 ); then
      log "macOS release $version already installed"
      printf '%s\n' "$executable_path"
      return 0
    fi
    log "reinstalling invalid macOS release $version"
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
  local actual_binary_sha256
  actual_binary_sha256=$(compute_sha256 "$executable_path")
  write_install_marker "$install_root" "macos" "$version" "$bundle_name/$binary_relative_path" "$actual_binary_sha256"
  verify_macos_install "$install_root" "$version" "$bundle_name" "$binary_relative_path" "$actual_binary_sha256"
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

if [ "$PLATFORM" = "linux" ]; then
  assert_supported_linux_arch "$asset_arch" "$resolved_version"
fi

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
