#!/usr/bin/env bash
# Makes the pin commit's two files (M13-D3, D39): run by the maintainer at a clean checkout of the
# commit A that phase 1 of the release built and signed. It holds and reads no key.
#
#   scripts/release/pin.sh [--rehearsal]
#
# It refuses unless, in this order: the work tree is clean (untracked files included); the list
# prebuilt-<version>.json and the envelope prebuilt-<version>.sig.json download from the draft
# v<version> (with --rehearsal: v<version>-rehearsal); the CLI's own parser accepts the list
# (`prebuilt check --json`; every value used below comes from that output, never from the raw file):
# its version is the workspace version, its source_commit is HEAD, and HEAD is an ancestor of
# origin/main (fetched by name; a missing ref is a failure); its rehearsal flag equals --rehearsal;
# `prebuilt verify` passes under the built-in key of the CLI built from this checkout
# (--allow-rehearsal only with --rehearsal). Only then it copies the two files, with cp, to
# crates/lunepack-cli/prebuilt.json and crates/lunepack-cli/prebuilt.sig.json and prints the next
# actions. It never commits, pushes, tags or signs.
#
# The CLI is built from this checkout (`cargo build --locked -p lunepack-cli`) unless LUNEPACK_CLI
# names one (the fixture test does). `gh` downloads from the repository of this checkout.
# bash 3.2 compatible (D30).
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

rehearsal=false
case $# in
  0) ;;
  1)
    [ "$1" = --rehearsal ] || {
      echo "usage: ${0##*/} [--rehearsal]" >&2
      exit 2
    }
    rehearsal=true
    ;;
  *)
    echo "usage: ${0##*/} [--rehearsal]" >&2
    exit 2
    ;;
esac
rel_need git gh jq

top=$(rel_top)
cd "$top"
[ -z "$(git status --porcelain --untracked-files=all)" ] || rel_die "the work tree is not clean"
head=$(rel_head)
version=$(rel_version)
if [ "$rehearsal" = true ]; then tag=v$version-rehearsal; else tag=v$version; fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-pin.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
list=$tmp/prebuilt-$version.json
sig=$tmp/prebuilt-$version.sig.json
gh release download "$tag" --pattern "prebuilt-$version.json" --pattern "prebuilt-$version.sig.json" --dir "$tmp" ||
  rel_die "cannot download the list and the envelope of the draft $tag"
[ -f "$list" ] && [ -f "$sig" ] || rel_die "the draft $tag lacks prebuilt-$version.json or prebuilt-$version.sig.json"

cli=$(rel_cli)
info=$("$cli" prebuilt check --list "$list" --json) || rel_die "the CLI's parser does not accept the draft's list"
lv=$(rel_json_str "$info" version)
commit=$(rel_json_str "$info" source_commit)
lr=$(rel_json_bool "$info" rehearsal)
[ "$lv" = "$version" ] || rel_die "the list's version $lv is not the workspace version $version"
[ "$commit" = "$head" ] || rel_die "the list's source_commit $commit is not HEAD $head: check out the commit the release was built from"
git fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main" || rel_die "cannot fetch main from origin"
git rev-parse --verify --quiet "refs/remotes/origin/main^{commit}" >/dev/null || rel_die "no origin/main after the fetch"
git merge-base --is-ancestor HEAD refs/remotes/origin/main || rel_die "HEAD is not on origin/main"
[ "$lr" = "$rehearsal" ] || rel_die "the list's rehearsal flag is $lr, this run expects $rehearsal"
allow=()
if [ "$rehearsal" = true ]; then allow=(--allow-rehearsal); fi
"$cli" prebuilt verify --list "$list" --sig "$sig" ${allow[@]+"${allow[@]}"} || rel_die "the envelope does not verify under this CLI's built-in key"

cp "$list" crates/lunepack-cli/prebuilt.json
cp "$sig" crates/lunepack-cli/prebuilt.sig.json

echo "copied the draft's list and envelope to crates/lunepack-cli/prebuilt.json and prebuilt.sig.json"
echo "next, by hand, in this order (this script runs none of them):"
if [ "$rehearsal" = true ]; then
  echo "  1. git switch -c release-rehearsal; commit exactly those two files"
  echo "  2. git push origin release-rehearsal"
  echo "  3. start the release workflow in mode rehearsal-finalize on the branch release-rehearsal"
  echo "  the branch is never merged and the draft $tag never published; delete both afterwards"
else
  echo "  1. commit exactly those two files (the pin commit; nothing else may change on main until the tag)"
  echo "  2. land that commit on main (a push or a merge; a squash merge is fine, its diff is the same two files)"
  echo "  3. only then tag the commit that is on main: git tag v$version <that commit>; git push origin v$version"
  echo "  a tag on a commit that is not on main fails the tag run"
fi
