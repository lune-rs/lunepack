#!/usr/bin/env bash
# Assembles a release from the built binaries (M13 step 14): the list of prebuilt binaries
# prebuilt-<version>.json (a FORMAT.md 21 payload), the third-party notices and SHA256SUMS.
#
#   scripts/release/assemble.sh <dry-run|binaries|rehearsal> <bin-dir> <out-dir>
#
# <bin-dir> must hold exactly the 20 files of the release matrix (M13-D19 as revised), named
# lunepack-<kind>-<version>-<target>[.exe]; a missing file, any other file or an empty one fails.
# <out-dir> (created, must be empty) receives a copy of each binary, the list, THIRD-PARTY-NOTICES.txt
# (crates/lunepack-cli/THIRD-PARTY-NOTICES.txt) and SHA256SUMS over all of them (C order, LF).
#
# The list: version = the workspace version; source_commit = HEAD of this checkout; rehearsal = false
# in mode `binaries` only (true in `rehearsal` and `dry-run`); rows sorted by target, then kind.
# jq writes it (sorted keys, LF, one final newline) and nothing reads it back here: the CLI's parser
# reads it before anything is signed (sign-list.sh; selftest in the dry run). Nothing may rewrite the
# file after this script: its bytes are what gets signed and pinned.
# bash 3.2 compatible (D30).
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

[ "$#" -eq 3 ] && [ -n "$2" ] && [ -n "$3" ] || {
  echo "usage: ${0##*/} <dry-run|binaries|rehearsal> <bin-dir> <out-dir>" >&2
  exit 2
}
mode=$1
bindir=$2
outdir=$3
rel_mode_ok "$mode" dry-run binaries rehearsal
rel_need jq git
if [ "$mode" = binaries ]; then rehearsal=false; else rehearsal=true; fi

[ -d "$bindir" ] || rel_die "the binary directory does not exist"
mkdir -p "$outdir"
[ -z "$(ls -A "$outdir")" ] || rel_die "the output directory is not empty"

version=$(rel_version)
commit=$(rel_head)
top=$(rel_top)
notices=$top/crates/lunepack-cli/THIRD-PARTY-NOTICES.txt
[ -f "$notices" ] && [ -s "$notices" ] || rel_die "no crates/lunepack-cli/THIRD-PARTY-NOTICES.txt"

# Every expected file present, regular and not empty; every file present expected.
expected=$(rel_matrix | while read -r k t; do rel_asset "$k" "$version" "$t"; done)
missing=
while IFS= read -r name; do
  if [ ! -f "$bindir/$name" ] || [ -L "$bindir/$name" ]; then
    missing="$missing $name"
  elif [ ! -s "$bindir/$name" ]; then
    rel_die "$name is empty"
  fi
done <<<"$expected"
extra=
for f in "$bindir"/* "$bindir"/.[!.]*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  if ! printf '%s\n' "$expected" | grep -Fxq -- "${f##*/}"; then
    extra="$extra ${f##*/}"
  fi
done
[ -z "$missing" ] || rel_die "missing from the release matrix:$missing"
[ -z "$extra" ] || rel_die "not in the release matrix:$extra"

rows=$(mktemp "${TMPDIR:-/tmp}/lunepack-rows.XXXXXX")
sums=$(mktemp "${TMPDIR:-/tmp}/lunepack-sums.XXXXXX")
trap 'rm -f "$rows" "$sums"' EXIT
rel_matrix | while read -r kind target; do
  name=$(rel_asset "$kind" "$version" "$target")
  cp "$bindir/$name" "$outdir/$name"
  size=$(rel_size "$outdir/$name")
  sha=$(rel_sha256 "$outdir/$name")
  jq -cn --arg kind "$kind" --arg target "$target" --argjson size "$size" --arg sha256 "$sha" \
    '{kind: $kind, target: $target, size: $size, sha256: $sha256}'
done >"$rows"
[ "$(wc -l <"$rows" | tr -d ' ')" -eq 20 ] || rel_die "the list does not have the 20 rows of the matrix"

list=prebuilt-$version.json
jq -S -s --arg version "$version" --arg commit "$commit" --argjson rehearsal "$rehearsal" \
  '{format: 1, kind: "prebuilt", critical: [], version: $version, source_commit: $commit, rehearsal: $rehearsal, binaries: .}' \
  "$rows" >"$outdir/$list"
cp "$notices" "$outdir/THIRD-PARTY-NOTICES.txt"

# In C order, whatever the locale: rel_check_release_files (attach, verify-pins.sh) rebuilds this file
# from the release's files and compares it byte for byte.
(
  cd "$outdir"
  printf '%s\n' * | LC_ALL=C sort | while IFS= read -r f; do
    sha=$(rel_sha256 "$f")
    printf '%s  %s\n' "$sha" "$f"
  done
) >"$sums"
cp "$sums" "$outdir/SHA256SUMS"

echo "assembled: $list (version $version, source commit $commit, rehearsal $rehearsal, 20 rows), THIRD-PARTY-NOTICES.txt, SHA256SUMS"
