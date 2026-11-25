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
