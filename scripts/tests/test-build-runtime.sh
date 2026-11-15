#!/usr/bin/env bash
# Tests for the argument check of scripts/build-runtime.sh. Nothing here runs cargo: a valid target
# is only ever given with --print-command.
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
SCRIPT=$here/../build-runtime.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

run_cmd bash "$SCRIPT"
t_check "no argument is a usage error" rc_is 2
t_check "usage is printed" out_has "usage:"

run_cmd bash "$SCRIPT" linux-x86_64 linux-aarch64
t_check "two targets are a usage error" rc_is 2

run_cmd bash "$SCRIPT" windows-x86_64
t_check "a non-Linux target is refused" rc_is 2
t_check "the refusal says so" out_has "unknown target"

run_cmd bash "$SCRIPT" x86_64-unknown-linux-musl
t_check "a triple is not a target id" rc_is 2

run_cmd bash "$SCRIPT" ""
t_check "an empty target is refused" rc_is 2

run_cmd bash "$SCRIPT" --print-command
t_check "--print-command alone is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --print-command linux-x86_64
t_check "x86_64 prints its command" rc_is 0
t_check "with the musl triple" out_has "--target x86_64-unknown-linux-musl"
t_check "locked and release" out_has "cargo build --locked --release -p lunepack-runtime"

run_cmd bash "$SCRIPT" --print-command linux-aarch64
t_check "aarch64 prints its command" rc_is 0
t_check "with its musl triple" out_has "--target aarch64-unknown-linux-musl"

run_cmd bash "$SCRIPT" --help
t_check "--help exits 0" rc_is 0

t_finish
