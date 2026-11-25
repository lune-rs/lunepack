#!/usr/bin/env bash
# Proves the pins before phase 2 of a release adds the CLI and publishes (M13-D3): run by the job
# `finalize` at the commit B being finalized.
#
#   scripts/release/verify-pins.sh <assets-dir> <tag|rehearsal-finalize>
#
# <assets-dir> holds the draft's files as stored (downloaded from the release). It fails unless:
#   - the draft holds exactly the release's files and nothing else (rel_check_release_files: the 20
#     binaries, the list, the envelope, THIRD-PARTY-NOTICES.txt equal to the committed file, and
#     SHA256SUMS equal to the SHA-256 of the others), so no file that nothing checks is published;
#   - the committed table crates/lunepack-cli/prebuilt.json equals the draft's prebuilt-<version>.json
#     and the committed envelope crates/lunepack-cli/prebuilt.sig.json equals the draft's
#     prebuilt-<version>.sig.json, byte for byte;
#   - `lunepack prebuilt verify --list <table> --sig <envelope> --dir <assets-dir> --all --json`
#     passes under the built-in key of the CLI built at B (--allow-rehearsal only in
#     rehearsal-finalize); from that output: the version is the workspace version, rehearsal is false
#     in tag mode and true in rehearsal-finalize, and source_commit (A) is an ancestor of B with A..B
#     changing exactly the two files above (so the key constants are the same at A and B);
#   - A is an ancestor of origin/main (fetched by name; a missing ref is a failure); in tag mode B is
#     an ancestor of origin/main too, and in rehearsal-finalize GITHUB_REF is exactly
#     refs/heads/release-rehearsal (mode.sh already refused any other; checked again here);
#   - the CLI's `prebuilt list --json` reports the state pinned (rehearsal-finalize: rehearsal) and
#     rows equal to the list's.
# The CLI is LUNEPACK_CLI (the workflow's CLI built at B), else built from this checkout. jq reads
# only what the CLI printed. bash 3.2 compatible (D30).
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

[ "$#" -eq 2 ] && [ -n "$1" ] || {
  echo "usage: ${0##*/} <assets-dir> <tag|rehearsal-finalize>" >&2
  exit 2
}
assets=$1
mode=$2
rel_mode_ok "$mode" tag rehearsal-finalize
rel_need git jq cmp
case $assets in
  /*) ;;
  *) assets=$PWD/$assets ;;
esac
[ -d "$assets" ] || rel_die "the assets directory does not exist"

top=$(rel_top)
cd "$top"
version=$(rel_version)
table=crates/lunepack-cli/prebuilt.json
envelope=crates/lunepack-cli/prebuilt.sig.json
[ -f "$assets/prebuilt-$version.json" ] || rel_die "the draft has no prebuilt-$version.json"
[ -f "$assets/prebuilt-$version.sig.json" ] || rel_die "the draft has no prebuilt-$version.sig.json"
cmp -s "$table" "$assets/prebuilt-$version.json" || rel_die "the committed table is not the draft's prebuilt-$version.json"
cmp -s "$envelope" "$assets/prebuilt-$version.sig.json" || rel_die "the committed envelope is not the draft's prebuilt-$version.sig.json"

cli=$(rel_cli)
allow=()
if [ "$mode" = rehearsal-finalize ]; then allow=(--allow-rehearsal); fi
v=$("$cli" prebuilt verify --list "$table" --sig "$envelope" --dir "$assets" --all --json ${allow[@]+"${allow[@]}"}) ||
  rel_die "prebuilt verify failed: the committed list, its envelope or the draft's files"
rel_check_release_files "$assets" "$version" present "$top/crates/lunepack-cli/THIRD-PARTY-NOTICES.txt"
lv=$(rel_json_str "$v" version)
a=$(rel_json_str "$v" source_commit)
lr=$(rel_json_bool "$v" rehearsal)
[ "$lv" = "$version" ] || rel_die "the list's version $lv is not the workspace version $version"
if [ "$mode" = tag ]; then want=false; else want=true; fi
[ "$lr" = "$want" ] || rel_die "the list's rehearsal flag is $lr, mode $mode needs $want"
printf '%s\n' "$a" | grep -Eq '^[0-9a-f]{40}$' || rel_die "the list's source_commit is not 40 hex"

git cat-file -e "$a^{commit}" 2>/dev/null || rel_die "the list's source_commit $a is not in this repository"
git merge-base --is-ancestor "$a" HEAD || rel_die "the list's source_commit $a is not an ancestor of HEAD"
changed=$(git diff --no-renames --name-only "$a" HEAD | LC_ALL=C sort)
[ "$changed" = "$(printf '%s\n%s' "$table" "$envelope")" ] ||
  rel_die "the commits from $a to HEAD change other files than the two pin files: $(printf '%s' "$changed" | tr '\n' ' ')"

git fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main" || rel_die "cannot fetch main from origin"
git rev-parse --verify --quiet "refs/remotes/origin/main^{commit}" >/dev/null || rel_die "no origin/main after the fetch"
git merge-base --is-ancestor "$a" refs/remotes/origin/main || rel_die "the list's source_commit $a is not on origin/main"
if [ "$mode" = tag ]; then
  git merge-base --is-ancestor HEAD refs/remotes/origin/main || rel_die "the tagged commit is not on origin/main"
else
  [ "${GITHUB_REF:-}" = refs/heads/release-rehearsal ] || rel_die "rehearsal-finalize runs on refs/heads/release-rehearsal only"
fi

l=$("$cli" prebuilt list --json) || rel_die "prebuilt list failed"
state=$(rel_json_str "$l" state)
if [ "$mode" = tag ]; then want=pinned; else want=rehearsal; fi
[ "$state" = "$want" ] || rel_die "the CLI built here is in the state $state, not $want"
rows_list=$(printf '%s\n' "$l" | jq -cS '.binaries | if type == "array" and length > 0 then . else error("no rows") end') ||
  rel_die "prebuilt list printed no rows"
rows_verify=$(printf '%s\n' "$v" | jq -cS '.binaries | if type == "array" and length > 0 then . else error("no rows") end') ||
  rel_die "prebuilt verify printed no rows"
[ "$rows_list" = "$rows_verify" ] || rel_die "the CLI's pinned rows are not the list's rows"

echo "pins proven: version $version, source commit $a, rehearsal $lr, state $state, files of the draft match"
