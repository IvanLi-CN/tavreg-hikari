#!/bin/sh
set -eu

sqlite_quote() {
  printf "%s" "$1" | sed "s/'/''/g"
}

snapshot_sqlite_with_bun() {
  src_path=$1
  dst_path=$2

  if ! command -v bun >/dev/null 2>&1; then
    return 1
  fi

  bun --eval '
    import { Database } from "bun:sqlite";

    const sourcePath = process.argv[1];
    const destPath = process.argv[2];
    const db = new Database(sourcePath);
    db.exec("PRAGMA busy_timeout = 5000;");
    const escapedDestPath = destPath.replaceAll("'"'"'", "'"'"''"'"'");
    db.exec(`VACUUM INTO '"'"'${escapedDestPath}'"'"'`);
    db.close(false);
  ' "$src_path" "$dst_path"
}

snapshot_sqlite() {
  src_path=$1
  dst_path=$2
  dst_sql=$(sqlite_quote "$dst_path")

  rm -f "$dst_path"
  if command -v sqlite3 >/dev/null 2>&1; then
    if sqlite3 "$src_path" \
      ".timeout 5000" \
      "VACUUM INTO '$dst_sql';"
    then
      return 0
    fi
    rm -f "$dst_path"
  fi

  snapshot_sqlite_with_bun "$src_path" "$dst_path"
}

if [ "$#" -ne 2 ]; then
  printf 'usage: %s <source-sqlite> <dest-sqlite>\n' "$0" >&2
  exit 64
fi

src_path=$1
dst_path=$2
mkdir -p "$(dirname -- "$dst_path")"
snapshot_sqlite "$src_path" "$dst_path"
