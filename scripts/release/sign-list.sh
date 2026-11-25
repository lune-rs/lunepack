#!/usr/bin/env bash
# Signs a release's list of prebuilt binaries with the project key (M13-D27, D35). Runs only in the
# release workflow's job `sign`, the one place that holds the key; the fixture test runs it with a
# throwaway key.
#
#   scripts/release/sign-list.sh <list> <out> <binaries|rehearsal>
#
# Environment: LUNEPACK_PROJECT_KEY (the key, PKCS#8 PEM text; read by the CLI only, through
# `--sign env:LUNEPACK_PROJECT_KEY`) and LUNEPACK_CLI (the lunepack CLI built at this commit by the
# same workflow run). It refuses, in this order, unless: shell tracing is off; the key variable is set
# and not empty; the mode is binaries or rehearsal; LUNEPACK_CLI names a regular file (made executable
# here: the artifact download drops the bit); <out> does not exist (its directory is made); the CLI's
# own parser accepts the list (`prebuilt check --json`) and, from that output, its version is the
# CLI's version (the workspace version at this commit), its source_commit is HEAD and its rehearsal
# flag is true exactly in mode rehearsal. Then `prebuilt sign`, which verifies under the CLI's
# built-in key before it writes, and `prebuilt verify` of what it wrote.
#
# It passes no trust flag, prints no environment and never expands the key variable: not into a
# command, an argument, a file or a log line.
# bash 3.2 compatible (D30).
set -euo pipefail

# Tracing would print every command of a step that holds the key: refuse before anything else.
case $- in
  *x*)
    echo "${0##*/}: shell tracing is on; refusing to run beside the project key" >&2
    exit 1
    ;;
esac

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

[ "$#" -eq 3 ] && [ -n "$1" ] && [ -n "$2" ] || {
  echo "usage: ${0##*/} <list> <out> <binaries|rehearsal>" >&2
  exit 2
}
list=$1
out=$2
mode=$3

# Set and not empty, tested through an expansion that never yields the value.
[ -n "${LUNEPACK_PROJECT_KEY:+set}" ] || rel_die "LUNEPACK_PROJECT_KEY is not set or empty: the environment secret is missing"
rel_mode_ok "$mode" binaries rehearsal
[ -n "${LUNEPACK_CLI:-}" ] && [ -f "$LUNEPACK_CLI" ] && [ ! -L "$LUNEPACK_CLI" ] || rel_die "LUNEPACK_CLI does not name a regular file"
chmod u+x "$LUNEPACK_CLI"
cli=$LUNEPACK_CLI
[ ! -e "$out" ] && [ ! -L "$out" ] || rel_die "the output already exists"
mkdir -p "$(dirname "$out")"
rel_need git jq

[ -f "$list" ] || rel_die "the list is not a file"
info=$("$cli" prebuilt check --list "$list" --json) || rel_die "the CLI's parser does not accept the list"
version=$(rel_json_str "$info" version)
commit=$(rel_json_str "$info" source_commit)
rehearsal=$(rel_json_bool "$info" rehearsal)

cli_version=$("$cli" --version) || rel_die "the CLI does not print its version"
[ "$cli_version" = "lunepack $version" ] || rel_die "the list's version $version is not the workspace version (${cli_version#lunepack })"
[ "$commit" = "$(rel_head)" ] || rel_die "the list's source_commit is not HEAD"
if [ "$mode" = rehearsal ]; then want=true; else want=false; fi
[ "$rehearsal" = "$want" ] || rel_die "the list's rehearsal flag is $rehearsal, mode $mode needs $want"

"$cli" prebuilt sign --list "$list" --out "$out" --sign env:LUNEPACK_PROJECT_KEY || rel_die "prebuilt sign refused the list (nothing was written)"
allow=()
if [ "$mode" = rehearsal ]; then allow=(--allow-rehearsal); fi
"$cli" prebuilt verify --list "$list" --sig "$out" ${allow[@]+"${allow[@]}"} || rel_die "the written envelope does not verify"
echo "signed: ${out##*/} (version $version, source commit $commit, rehearsal $rehearsal)"
