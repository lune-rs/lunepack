#!/usr/bin/env bash
# The release workflow's mode (M13 step 14): the only reader of the event, the ref and the input.
#
#   scripts/release/mode.sh        # prints "mode=<mode>" and "version=<version>"; nothing else
#
# Inputs, from the environment only (the workflow never puts them into a script's text):
#   GITHUB_EVENT_NAME     push | workflow_dispatch
#   GITHUB_REF            refs/heads/<branch> | refs/tags/<tag>
#   LUNEPACK_INPUT_MODE   the dispatch input `mode` (dispatch only)
# The version is the workspace version (cargo metadata of this checkout).
#
#   push of refs/tags/v<version>                  -> tag
#   push of any other tag                         -> refused
#   push of a branch                              -> dry-run (the workflow limits it to main and orch/**)
#   dispatch dry-run                              -> dry-run (any branch)
#   dispatch binaries | rehearsal                 -> only on refs/heads/main
#   dispatch rehearsal-finalize                   -> only on refs/heads/release-rehearsal
#   anything else (another event or input, a dispatch on a tag) -> refused
#
# The two printed values carry only a mode name and MAJOR.MINOR.PATCH: no shell or path character.
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

event=${GITHUB_EVENT_NAME:-}
ref=${GITHUB_REF:-}
input=${LUNEPACK_INPUT_MODE:-}
[ -n "$event" ] || rel_die "GITHUB_EVENT_NAME is not set"
[ -n "$ref" ] || rel_die "GITHUB_REF is not set"

version=$(rel_version)

case $event in
  push)
    [ -z "$input" ] || rel_die "a push has no mode input"
    case $ref in
      "refs/tags/v$version") mode=tag ;;
      refs/tags/*) rel_die "the tag is not v$version (the workspace version)" ;;
      refs/heads/?*) mode=dry-run ;;
      *) rel_die "unrecognised ref" ;;
    esac
    ;;
  workflow_dispatch)
    case $ref in
      refs/heads/?*) ;;
      *) rel_die "a dispatch runs on a branch only" ;;
    esac
    case $input in
      dry-run) mode=dry-run ;;
      binaries | rehearsal)
        [ "$ref" = refs/heads/main ] || rel_die "mode $input runs on refs/heads/main only"
        mode=$input
        ;;
      rehearsal-finalize)
        [ "$ref" = refs/heads/release-rehearsal ] || rel_die "mode rehearsal-finalize runs on refs/heads/release-rehearsal only"
        mode=$input
        ;;
      *) rel_die "unrecognised mode input" ;;
    esac
    ;;
  *) rel_die "unrecognised event" ;;
esac

echo "mode=$mode"
echo "version=$version"
