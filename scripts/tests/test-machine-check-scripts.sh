#!/usr/bin/env bash
# Tests for the guards of the scripts that need a disposable machine or a person (M11 step 14):
# scripts/e2e-macos-machine.sh, scripts/macos-machine-user-check.sh and
# scripts/linux-machine-user-check.sh. Nothing here builds, installs, asks or needs root: only
# invalid arguments, --help, --dry-run (every row SKIPPED), the refusals in their order, and a scan
# that none of them is wired into the gate or CI.
# SC2016: `bash -c '...' _ args` keeps its program in single quotes on purpose.
# shellcheck disable=SC2016
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
top=$(cd "$here/../.." && pwd)
SUITE=$here/../e2e-macos-machine.sh
MAC_CHECK=$here/../macos-machine-user-check.sh
LINUX_CHECK=$here/../linux-machine-user-check.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init
os=$(uname -s)
uid=$(id -u)

# ---- scripts/e2e-macos-machine.sh ------------------------------------------------------------------

run_cmd bash "$SUITE" --bogus
t_check "suite: an unknown option is a usage error" rc_is 2
t_check "suite: usage is printed" out_has "usage:"

run_cmd bash "$SUITE" extra
t_check "suite: a stray argument is a usage error" rc_is 2

run_cmd bash "$SUITE" --help
t_check "suite: --help exits 0" rc_is 0

run_cmd bash "$SUITE" --dry-run
t_check "suite: --dry-run exits 0" rc_is 0
t_check "suite: --dry-run says nothing runs" out_has "nothing is built, installed or changed"
rows=$(grep -c '^  SKIPPED  ' "$OUT" || true)
t_check "suite: --dry-run lists 15 rows, every one SKIPPED" test "$rows" -eq 15
t_check "suite: --dry-run reports no failure" bash -c '! grep -q "^ *FAIL" "$1"' _ "$OUT"
for row in "installer -pkg as root" "the supervisor killed" "the daemon disabled" "uninstall" "policy file"; do
  t_check "suite: --dry-run names the row '$row'" out_has "$row"
done

run_cmd bash "$SUITE" --dry-run --disposable
t_check "suite: --dry-run with --disposable is a usage error" rc_is 2

# The refusals, in their order: the flag, the variable, the system, root.
run_cmd bash "$SUITE"
t_check "suite: without --disposable it refuses" rc_is 1
t_check "suite: and names the flag" out_has "--disposable"

run_cmd env -u LUNEPACK_E2E_MACHINE_OK bash "$SUITE" --disposable
t_check "suite: without the variable it refuses" rc_is 1
t_check "suite: and names the variable" out_has "LUNEPACK_E2E_MACHINE_OK=1"

run_cmd env LUNEPACK_E2E_MACHINE_OK=0 bash "$SUITE" --disposable
t_check "suite: a variable that is not 1 refuses" rc_is 1

if [ "$os" != Darwin ]; then
  run_cmd env LUNEPACK_E2E_MACHINE_OK=1 bash "$SUITE" --disposable
  t_check "suite: off macOS it refuses" rc_is 1
  t_check "suite: and says macOS only" out_has "macOS only"
elif [ "$uid" != 0 ]; then
  run_cmd env LUNEPACK_E2E_MACHINE_OK=1 bash "$SUITE" --disposable
  t_check "suite: not root it refuses" rc_is 1
  t_check "suite: and says it needs root" out_has "needs root"
fi

# ---- scripts/macos-machine-user-check.sh -----------------------------------------------------------

run_cmd bash "$MAC_CHECK" --bogus
t_check "macOS check: an unknown option is a usage error" rc_is 2

run_cmd bash "$MAC_CHECK"
t_check "macOS check: without --standard-user it is a usage error" rc_is 2

run_cmd bash "$MAC_CHECK" --standard-user
t_check "macOS check: --standard-user needs a value" rc_is 2

run_cmd bash "$MAC_CHECK" --dry-run
t_check "macOS check: --dry-run exits 0" rc_is 0
stages=$(grep -c '^  SKIPPED  ' "$OUT" || true)
t_check "macOS check: --dry-run lists 5 stages, every one SKIPPED" test "$stages" -eq 5
t_check "macOS check: --dry-run names Login Items" out_has "Login Items"

run_cmd bash "$MAC_CHECK" --dry-run --standard-user x
t_check "macOS check: --dry-run with --standard-user is a usage error" rc_is 2

run_cmd bash "$MAC_CHECK" --standard-user nobody
t_check "macOS check: a run is refused here" rc_is 1
if [ "$os" != Darwin ]; then
  t_check "macOS check: off macOS it says macOS only" out_has "macOS only"
elif [ "$uid" = 0 ]; then
  t_check "macOS check: as root it says so" out_has "as root"
else
  t_check "macOS check: without a terminal it says so" out_has "without a terminal"
fi

# ---- scripts/linux-machine-user-check.sh -----------------------------------------------------------

run_cmd bash "$LINUX_CHECK" --bogus
t_check "Linux check: an unknown option is a usage error" rc_is 2

run_cmd bash "$LINUX_CHECK"
t_check "Linux check: without --standard-user it is a usage error" rc_is 2

run_cmd bash "$LINUX_CHECK" --dry-run
t_check "Linux check: --dry-run exits 0" rc_is 0
stages=$(grep -c '^  SKIPPED  ' "$OUT" || true)
t_check "Linux check: --dry-run lists 4 stages, every one SKIPPED" test "$stages" -eq 4
t_check "Linux check: --dry-run names pkexec" out_has "pkexec"

run_cmd bash "$LINUX_CHECK" --dry-run --standard-user x
t_check "Linux check: --dry-run with --standard-user is a usage error" rc_is 2

run_cmd bash "$LINUX_CHECK" --standard-user nobody
t_check "Linux check: a run is refused here" rc_is 1
if [ "$os" != Linux ]; then
  t_check "Linux check: off Linux it says Linux only" out_has "Linux only"
elif [ "$uid" = 0 ]; then
  t_check "Linux check: as root it says so" out_has "as root"
else
  t_check "Linux check: without a terminal it says so" out_has "without a terminal"
fi

# ---- never in the gate or CI -------------------------------------------------------------------

t_check "none of the three is run by the gate" bash -c '! grep -nE "e2e-macos-machine|macos-machine-user-check|linux-machine-user-check" "$1/scripts/gate.sh"' _ "$top"
t_check "none of the three is named by a workflow" bash -c '! grep -rnE "e2e-macos-machine|macos-machine-user-check|linux-machine-user-check" "$1/.github" 2>/dev/null' _ "$top"
# shellcheck disable=SC2016
t_check "the suite removes nothing by a bare root, home or tilde" bash -c '! grep -nE "rm -rf (/|[$]HOME|~)( |$)" "$1"' _ "$SUITE"
t_check "the suite never prints the password it made" bash -c '! grep -nE "(echo|printf)[^|]*[$]pw" "$1"' _ "$SUITE"

t_finish
