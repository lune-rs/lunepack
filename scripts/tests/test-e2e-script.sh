#!/usr/bin/env bash
# Tests for the argument handling of scripts/e2e.sh and scripts/e2e-macos.sh. Nothing here starts
# Docker or a suite: only invalid arguments, --help, and the refusals off the suite's own OS.
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
SCRIPT=$here/../e2e.sh
MAC_SCRIPT=$here/../e2e-macos.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

run_cmd bash "$SCRIPT" --bogus
t_check "an unknown option is a usage error" rc_is 2
t_check "usage is printed" out_has "usage:"

run_cmd bash "$SCRIPT" extra
t_check "a stray argument is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --runtime /nowhere
t_check "--runtime without --inside is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --inside --runtime
t_check "--runtime without a value is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --inside --runtime ""
t_check "an empty --runtime is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --help
t_check "--help exits 0" rc_is 0
t_check "--help prints usage" out_has "usage:"

if [ "$(uname -s)" != Linux ]; then
  run_cmd bash "$SCRIPT" --inside
  t_check "--inside off Linux is refused" rc_is 1
  t_check "the refusal says Linux only" out_has "Linux only"
fi

run_cmd bash "$MAC_SCRIPT" --bogus
t_check "e2e-macos: an unknown option is a usage error" rc_is 2
t_check "e2e-macos: usage is printed" out_has "usage:"

run_cmd bash "$MAC_SCRIPT" extra
t_check "e2e-macos: a stray argument is a usage error" rc_is 2

run_cmd bash "$MAC_SCRIPT" --help
t_check "e2e-macos: --help exits 0" rc_is 0
t_check "e2e-macos: --help prints usage" out_has "usage:"

if [ "$(uname -s)" != Darwin ]; then
  run_cmd bash "$MAC_SCRIPT"
  t_check "e2e-macos: a run off macOS is refused" rc_is 1
  t_check "e2e-macos: the refusal says macOS only" out_has "macOS only"
fi

t_finish
