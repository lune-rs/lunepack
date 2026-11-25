#!/usr/bin/env bash
# Shared helpers of the release scripts (M13 step 14). Sourced, never run: `. scripts/release/lib.sh`.
# Every helper fails closed: a tool that prints nothing recognisable is an error, never a default.
# The release scripts read a list of prebuilt binaries only through the CLI's own parser
# (`lunepack prebuilt check|verify|list --json`); jq reads only what the CLI wrote.
# bash 3.2 compatible (D30).
# shellcheck shell=bash

# rel_die <message>: prints "<script>: <message>" on stderr and exits 1.
rel_die() {
  echo "${0##*/}: $*" >&2
  exit 1
}

# rel_need <tool>...: fails unless every tool is on PATH.
rel_need() {
  local t
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || rel_die "$t is not on PATH"
  done
}

# rel_top: the top level of the git work tree the caller is in.
rel_top() {
  git rev-parse --show-toplevel 2>/dev/null || rel_die "not inside a git work tree"
}

# rel_head: the 40-hex commit of HEAD.
rel_head() {
  local h
  h=$(git rev-parse --verify "HEAD^{commit}" 2>/dev/null) || rel_die "HEAD is not a commit"
  printf '%s\n' "$h" | grep -Eq '^[0-9a-f]{40}$' || rel_die "HEAD is not 40 lowercase hex"
  printf '%s\n' "$h"
}

# rel_version [top]: the workspace version (the version of the package lunepack-cli), from cargo
# metadata of the workspace at <top> (default: the git work tree the caller is in). Only
# MAJOR.MINOR.PATCH digits pass: the value reaches file names, release names and workflow outputs.
rel_version() {
  local top=${1:-} v
  [ -n "$top" ] || top=$(rel_top)
  v=$(cargo metadata --no-deps --offline --format-version 1 --manifest-path "$top/Cargo.toml" 2>/dev/null |
    jq -er '[.packages[] | select(.name == "lunepack-cli") | .version] | if length == 1 then .[0] else error("lunepack-cli not found once") end') ||
    rel_die "cannot read the workspace version (cargo metadata, package lunepack-cli)"
  printf '%s\n' "$v" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
    rel_die "the workspace version is not MAJOR.MINOR.PATCH"
  printf '%s\n' "$v"
}

# rel_sha256 <file>: the file's SHA-256 as 64 lowercase hex (sha256sum, or shasum -a 256 on macOS).
rel_sha256() {
  local out
  if command -v sha256sum >/dev/null 2>&1; then
    out=$(sha256sum -b "$1") || rel_die "sha256sum failed on $1"
  elif command -v shasum >/dev/null 2>&1; then
    out=$(shasum -a 256 -b "$1") || rel_die "shasum failed on $1"
  else
    rel_die "neither sha256sum nor shasum is on PATH"
  fi
  out=${out%% *}
  printf '%s\n' "$out" | grep -Eq '^[0-9a-f]{64}$' || rel_die "the SHA-256 of $1 is not 64 lowercase hex"
  printf '%s\n' "$out"
}

# rel_size <file>: the file's length in bytes.
rel_size() {
  local n
  n=$(wc -c <"$1") || rel_die "cannot read $1"
  n=${n//[[:space:]]/}
  printf '%s\n' "$n" | grep -Eq '^[0-9]+$' || rel_die "wc printed no size for $1"
  printf '%s\n' "$n"
}

# rel_matrix: the (kind, target) pairs of a release (M13-D19 as revised: 20 files), one
# "<kind> <target>" per line, sorted by target, then kind.
rel_matrix() {
  local k t
  for t in linux-aarch64 linux-x86_64 macos-aarch64 macos-universal macos-x86_64; do
    for k in runtime service ui; do
      echo "$k $t"
    done
  done
  for k in runtime service stub stub-console ui; do
    echo "$k windows-x86_64"
  done
}

# rel_asset <kind> <version> <target>: the release asset name (FORMAT 21; `.exe` on windows-*).
rel_asset() {
  case $3 in
    windows-*) echo "lunepack-$1-$2-$3.exe" ;;
    *) echo "lunepack-$1-$2-$3" ;;
  esac
}

# rel_check_release_files <dir> <version> <envelope> <notices>: fails unless <dir> holds exactly the
# files that assemble.sh wrote and the envelope, as regular files, and nothing else: the 20 binaries
# of the matrix, prebuilt-<version>.json, THIRD-PARTY-NOTICES.txt, SHA256SUMS, and
# prebuilt-<version>.sig.json as <envelope> says (absent, present or either). Checked by content
# here: THIRD-PARTY-NOTICES.txt equals <notices> (the committed file) byte for byte, and SHA256SUMS
# is the SHA-256 of the other 22 files in assemble.sh's form (C order, LF) byte for byte. The
# binaries and the list are left to `prebuilt verify --all` under the signed envelope, and the
# envelope to its signature: run it beside this, never instead.
rel_check_release_files() {
  [ "$#" -eq 4 ] || rel_die "rel_check_release_files takes 4 arguments"
  local dir=$1 version=$2 envelope=$3 notices=$4 list sig names allowed f n a ok h missing='' extra='' sums=''
  rel_need cmp
  case $envelope in
    absent | present | either) ;;
    *) rel_die "rel_check_release_files: envelope '$envelope' is not absent, present or either" ;;
  esac
  [ -d "$dir" ] && [ ! -L "$dir" ] || rel_die "the release directory does not exist"
  [ -f "$notices" ] || rel_die "no committed notices file to compare with"
  list=prebuilt-$version.json
  sig=prebuilt-$version.sig.json
  names=$(rel_matrix | while read -r k t; do rel_asset "$k" "$version" "$t"; done)
  names=$(printf '%s\n%s\n%s' "$names" "$list" THIRD-PARTY-NOTICES.txt)
  allowed=$(printf '%s\nSHA256SUMS' "$names")
  [ "$envelope" = absent ] || allowed=$(printf '%s\n%s' "$allowed" "$sig")
  # Every entry is one of the allowed names (compared whole, so a name with a newline in it never
  # matches one of its lines) and a regular file.
  for f in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    n=${f##*/}
    ok=
    while IFS= read -r a; do
      if [ "$a" = "$n" ]; then
        ok=1
        break
      fi
    done <<<"$allowed"
    if [ -z "$ok" ]; then
      extra="$extra $n"
    elif [ ! -f "$f" ] || [ -L "$f" ]; then
      rel_die "$n is not a regular file"
    fi
  done
  [ -z "$extra" ] || rel_die "files outside the release's expected set:$extra"
  while IFS= read -r n; do
    [ -f "$dir/$n" ] || missing="$missing $n"
  done <<<"$(printf '%s\nSHA256SUMS' "$names")"
  if [ "$envelope" = present ] && [ ! -f "$dir/$sig" ]; then missing="$missing $sig"; fi
  [ -z "$missing" ] || rel_die "missing from the release:$missing"
  cmp -s "$notices" "$dir/THIRD-PARTY-NOTICES.txt" || rel_die "THIRD-PARTY-NOTICES.txt is not the committed notices file"
  while IFS= read -r n; do
    h=$(rel_sha256 "$dir/$n")
    sums="$sums$h  $n
"
  done <<<"$(printf '%s\n' "$names" | LC_ALL=C sort)"
  printf '%s' "$sums" | cmp -s - "$dir/SHA256SUMS" || rel_die "SHA256SUMS is not the SHA-256 of the release's files"
}

# rel_mode_ok <mode> <allowed>...: fails unless the mode is one of the allowed names.
rel_mode_ok() {
  local m=$1 a
  shift
  for a in "$@"; do
    [ "$m" = "$a" ] && return 0
  done
  rel_die "mode '$m' is not allowed here (allowed: $*)"
}

# rel_cli: the lunepack CLI the scripts run: $LUNEPACK_CLI when set (a regular executable file),
# else the CLI built from the work tree the caller is in (`cargo build --locked -p lunepack-cli`,
# into that tree's target directory). Prints its path.
rel_cli() {
  local top
  if [ -n "${LUNEPACK_CLI:-}" ]; then
    [ -f "$LUNEPACK_CLI" ] && [ -x "$LUNEPACK_CLI" ] || rel_die "LUNEPACK_CLI does not name an executable file"
    printf '%s\n' "$LUNEPACK_CLI"
    return 0
  fi
  top=$(rel_top)
  (cd "$top" && cargo build --quiet --locked -p lunepack-cli >&2) || rel_die "cargo build -p lunepack-cli failed"
  [ -x "${CARGO_TARGET_DIR:-$top/target}/debug/lunepack" ] || rel_die "the build left no target/debug/lunepack"
  printf '%s\n' "${CARGO_TARGET_DIR:-$top/target}/debug/lunepack"
}

# rel_json_str <json> <member>: a string member of an object the CLI printed (jq -e: a missing
# member, null or another type fails).
rel_json_str() {
  printf '%s\n' "$1" | jq -er --arg m "$2" '.[$m] | if type == "string" then . else error("not a string") end' 2>/dev/null ||
    rel_die "the CLI's output has no string member '$2'"
}

# rel_json_bool <json> <member>: a boolean member, printed as true or false.
rel_json_bool() {
  printf '%s\n' "$1" | jq -er --arg m "$2" '.[$m] | if type == "boolean" then tostring else error("not a boolean") end' 2>/dev/null ||
    rel_die "the CLI's output has no boolean member '$2'"
}
