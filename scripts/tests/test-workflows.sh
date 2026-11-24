#!/usr/bin/env bash
# Lint .github/workflows/*.yml with plain text rules (fail closed: at least one workflow
# must exist). Each rule is also seeded against a bad temp copy to prove it can fail.
#   test-workflows.sh [workflow-dir]     (default: <repo>/.github/workflows)
# Rules per file: a column-0 `permissions:` line; no pull_request_target; no `secrets.`;
# every `uses:` is ./... or owner/repo[/path]@<40 hex>; no `write` permission anywhere.
# bash 3.2 compatible.
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

# lint_file <file>: prints one line per violation; returns nonzero when there is any.
lint_file() {
  local f=$1 bad=0
  if ! grep -q '^permissions:' "$f"; then echo "no top-level permissions: line"; bad=1; fi
  if grep -qi 'pull_request_target' "$f"; then echo "pull_request_target is not allowed"; bad=1; fi
  if grep -q 'secrets\.' "$f"; then echo "secrets. reference is not allowed"; bad=1; fi
  if grep -Eqi '(^|[^A-Za-z0-9_-])write([^A-Za-z0-9_-]|$)' "$f"; then echo "write permission/word is not allowed"; bad=1; fi
  local line value
  while IFS= read -r line; do
    value=${line#*uses:}
    value=${value%%#*}
    value=$(printf '%s' "$value" | tr -d ' \t\r"'"'")
    case $value in
      ./*) ;;
      *)
        if ! printf '%s\n' "$value" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$'; then
          echo "uses: not pinned to a 40-hex commit: $value"
          bad=1
        fi
        ;;
    esac
  done < <(grep -E '^[[:space:]-]*uses:' "$f" || true)
  return "$bad"
}

# lint_dir <dir>: lints every *.yml in it; nonzero when there is none (fail closed) or any
# file has a violation.
lint_dir() {
  local d=$1 f n=0 bad=0
  for f in "$d"/*.yml; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    if ! lint_file "$f" >"$T_TMP/file-out.txt" 2>&1; then
      bad=1
      sed "s|^|${f##*/}: |" "$T_TMP/file-out.txt"
    fi
  done
  if [ "$n" -eq 0 ]; then echo "no workflow files found in the directory"; return 1; fi
  return "$bad"
}

t_init
dir=${1:-$here/../../.github/workflows}

RC=0
lint_dir "$dir" >"$OUT" 2>&1 || RC=$?
t_check "the real workflows pass the lint (and at least one exists)" rc_is 0
if [ "$RC" -ne 0 ]; then sed 's/^/    /' "$OUT" >&2; fi

# --- seeded negatives: each bad copy must fail with the expected message ------------------
seed() { # name, content, expected message
  local f=$T_TMP/$1.yml
  printf '%s\n' "$2" >"$f"
  RC=0
  lint_file "$f" >"$OUT" 2>&1 || RC=$?
  t_check "seeded $1 fails" rc_nonzero
  t_check "seeded $1 reports: $3" out_has "$3"
}
sha=0123456789abcdef0123456789abcdef01234567
good="on: push
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$sha # v1"
printf '%s\n' "$good" >"$T_TMP/good.yml"
RC=0
lint_file "$T_TMP/good.yml" >"$OUT" 2>&1 || RC=$?
t_check "seeded good copy passes (control)" rc_is 0

seed tag-pinned "$(printf '%s\n' "$good" | sed 's|@[0-9a-f]\{40\}|@v4|')" "not pinned"
seed short-sha "$(printf '%s\n' "$good" | sed 's|@[0-9a-f]\{40\}|@0123abc|')" "not pinned"
seed branch-pinned "$(printf '%s\n' "$good" | sed 's|@[0-9a-f]\{40\}|@main|')" "not pinned"
seed unpinned "$(printf '%s\n' "$good" | sed 's|@[0-9a-f]\{40\}||')" "not pinned"
seed prt "$(printf '%s\n' "$good" | sed 's|on: push|on: pull_request_target|')" "pull_request_target"
seed secrets "$good
      - run: echo \${{ secrets.TOKEN }}" "secrets."
seed no-permissions "$(printf '%s\n' "$good" | sed '/^permissions:/,/^  contents/d')" "permissions:"
seed write-perm "$(printf '%s\n' "$good" | sed 's|contents: read|contents: write|')" "write"
seed indented-permissions-only "on: push
jobs:
  j:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@$sha" "permissions:"

# Seeds derived from the real workflows: one tag-pinned uses, one pull_request_target.
mkdir -p "$T_TMP/real-seed"
for f in "$dir"/*.yml; do
  [ -f "$f" ] || continue
  sed 's|\(uses: [^@ ]*\)@[0-9a-f]\{40\}|\1@v4|' "$f" >"$T_TMP/real-seed/tag.yml"
  RC=0
  lint_dir "$T_TMP/real-seed" >"$OUT" 2>&1 || RC=$?
  t_check "a tag-pinned copy of ${f##*/} fails" rc_nonzero
  rm -f "$T_TMP/real-seed/tag.yml"
  sed 's|^on:|on:\n  pull_request_target:|' "$f" >"$T_TMP/real-seed/prt.yml"
  RC=0
  lint_dir "$T_TMP/real-seed" >"$OUT" 2>&1 || RC=$?
  t_check "a pull_request_target copy of ${f##*/} fails" rc_nonzero
  rm -f "$T_TMP/real-seed/prt.yml"
done

# --- fail closed: an empty dir has no workflows -----------------------------------------
mkdir -p "$T_TMP/empty"
RC=0
lint_dir "$T_TMP/empty" >"$OUT" 2>&1 || RC=$?
t_check "an empty workflow dir fails" rc_nonzero
t_check "an empty workflow dir says why" out_has "no workflow files"
RC=0
lint_dir "$T_TMP/does-not-exist" >"$OUT" 2>&1 || RC=$?
t_check "a missing workflow dir fails" rc_nonzero

# A dir holding one bad and one good file fails and names the bad one.
mkdir -p "$T_TMP/mixed"
cp "$T_TMP/good.yml" "$T_TMP/mixed/good.yml"
cp "$T_TMP/tag-pinned.yml" "$T_TMP/mixed/bad.yml"
RC=0
lint_dir "$T_TMP/mixed" >"$OUT" 2>&1 || RC=$?
t_check "a dir with one bad file fails" rc_nonzero
t_check "the bad file is named" out_has "bad.yml:"
t_check "the good file is not named" out_lacks "good.yml:"

# --- the os-trust job (M4 step 14) --------------------------------------------------------
# A regression check on the real adapter: it must be a required job with a time bound, and its
# scripts must refuse to run off CI (they change the OS trust store and proxy settings).
repo=$(cd "$here/../.." && pwd)
ci=$repo/.github/workflows/ci.yml

# job_block <file> <job>: the lines of one top-level job.
job_block() {
  awk -v job="  $2:" '
    $0 == job { on = 1; print; next }
    on && /^  [A-Za-z0-9_-]+:/ { exit }
    on { print }
  ' "$1"
}

# os_trust_job_ok <file>: prints one line per problem; nonzero when there is any.
os_trust_job_ok() {
  local block bad=0 os
  block=$(job_block "$1" os-trust)
  if [ -z "$block" ]; then echo "no os-trust job"; return 1; fi
  if ! printf '%s\n' "$block" | grep -q 'timeout-minutes:'; then echo "os-trust has no timeout-minutes"; bad=1; fi
  if printf '%s\n' "$block" | grep -q 'continue-on-error'; then echo "os-trust must not be continue-on-error"; bad=1; fi
  for os in ubuntu-latest macos-latest windows-latest; do
    if ! printf '%s\n' "$block" | grep -q "$os"; then echo "os-trust does not run on $os"; bad=1; fi
  done
  if ! printf '%s\n' "$block" | grep -q 'scripts/ci/os-trust.sh'; then echo "os-trust does not run os-trust.sh"; bad=1; fi
  if ! printf '%s\n' "$block" | grep -q 'scripts/ci/os-trust.ps1'; then echo "os-trust does not run os-trust.ps1"; bad=1; fi
  return "$bad"
}

if [ -f "$ci" ]; then
  RC=0
  os_trust_job_ok "$ci" >"$OUT" 2>&1 || RC=$?
  t_check "ci.yml has a required, time-bounded os-trust job on three OSes" rc_is 0
  if [ "$RC" -ne 0 ]; then sed 's/^/    /' "$OUT" >&2; fi
  # seeded negatives: the check can fail
  sed 's|^  os-trust:|  os-trust:\n    continue-on-error: true|' "$ci" >"$T_TMP/coe.yml"
  RC=0
  os_trust_job_ok "$T_TMP/coe.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded continue-on-error on os-trust fails" rc_nonzero
  t_check "seeded continue-on-error reports why" out_has "continue-on-error"
  grep -v 'timeout-minutes' "$ci" >"$T_TMP/no-timeout.yml" || true
  RC=0
  os_trust_job_ok "$T_TMP/no-timeout.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded os-trust without a timeout fails" rc_nonzero
  t_check "seeded missing timeout reports why" out_has "no timeout-minutes"
  RC=0
  os_trust_job_ok "$T_TMP/good.yml" >"$OUT" 2>&1 || RC=$?
  t_check "a file with no os-trust job fails" rc_nonzero
fi

# --- the Windows end-to-end jobs (M7 step 14) ---------------------------------------------
# Both must be required (no continue-on-error), time-bounded and on a Windows runner; the
# Defender job turns Defender on first and reports detections whatever the suite did.
e2e_windows_jobs_ok() {
  local block bad=0 job
  for job in e2e-windows e2e-windows-defender; do
    block=$(job_block "$1" "$job")
    if [ -z "$block" ]; then echo "no $job job"; bad=1; continue; fi
    if ! printf '%s\n' "$block" | grep -q 'timeout-minutes:'; then echo "$job has no timeout-minutes"; bad=1; fi
    if printf '%s\n' "$block" | grep -q 'continue-on-error'; then echo "$job must not be continue-on-error"; bad=1; fi
    if ! printf '%s\n' "$block" | grep -q 'runs-on: windows-latest'; then echo "$job does not run on windows-latest"; bad=1; fi
    if ! printf '%s\n' "$block" | grep -q 'scripts/e2e-windows.ps1'; then echo "$job does not run e2e-windows.ps1"; bad=1; fi
  done
  block=$(job_block "$1" e2e-windows)
  if ! printf '%s\n' "$block" | grep -q 'run: ./scripts/ci/windows-publisher-test.ps1'; then echo "e2e-windows does not run windows-publisher-test.ps1"; bad=1; fi
  block=$(job_block "$1" e2e-windows-defender)
  if ! printf '%s\n' "$block" | grep -q 'scripts/ci/defender-on.ps1'; then echo "the Defender job does not run defender-on.ps1"; bad=1; fi
  if ! printf '%s\n' "$block" | grep -q 'defender-on.ps1 -Report'; then echo "the Defender job does not report detections"; bad=1; fi
  if ! printf '%s\n' "$block" | grep -q 'if: always()'; then echo "the Defender job's report does not run after a failure"; bad=1; fi
  return "$bad"
}

if [ -f "$ci" ]; then
  RC=0
  e2e_windows_jobs_ok "$ci" >"$OUT" 2>&1 || RC=$?
  t_check "ci.yml has the e2e-windows and e2e-windows-defender jobs, required and time-bounded" rc_is 0
  if [ "$RC" -ne 0 ]; then sed 's/^/    /' "$OUT" >&2; fi
  sed 's|^  e2e-windows-defender:|  e2e-windows-defender:\n    continue-on-error: true|' "$ci" >"$T_TMP/e2e-coe.yml"
  RC=0
  e2e_windows_jobs_ok "$T_TMP/e2e-coe.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded continue-on-error on the Defender job fails" rc_nonzero
  t_check "seeded continue-on-error reports why" out_has "continue-on-error"
  grep -v 'defender-on.ps1 -Report' "$ci" >"$T_TMP/e2e-noreport.yml" || true
  RC=0
  e2e_windows_jobs_ok "$T_TMP/e2e-noreport.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded Defender job without its report fails" rc_nonzero
  grep -v 'windows-publisher-test.ps1' "$ci" >"$T_TMP/e2e-nopub.yml" || true
  RC=0
  e2e_windows_jobs_ok "$T_TMP/e2e-nopub.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded e2e-windows without the publisher test fails" rc_nonzero
  t_check "seeded e2e-windows without the publisher test reports why" out_has "windows-publisher-test.ps1"
  RC=0
  e2e_windows_jobs_ok "$T_TMP/good.yml" >"$OUT" 2>&1 || RC=$?
  t_check "a file with no Windows e2e jobs fails" rc_nonzero
fi

t_check "defender-on.ps1 refuses off GitHub Actions" grep -q "GITHUB_ACTIONS -ne 'true'" "$repo/scripts/ci/defender-on.ps1"
if command -v pwsh >/dev/null 2>&1; then
  RC=0
  env -u CI -u GITHUB_ACTIONS pwsh -NoProfile -File "$repo/scripts/ci/defender-on.ps1" >"$OUT" 2>&1 || RC=$?
  t_check "defender-on.ps1 refuses off CI: exit 3" rc_is 3
fi

# windows-machine-adapter-test.ps1 refuses off CI without -Install (exit 3) before it touches
# anything; its administrator check and its leftover check are in the text.
# shellcheck disable=SC2016  # the script's own PowerShell text, searched literally
t_check "windows-machine-adapter-test.ps1 asks for CI or -Install" grep -q 'if (-not $Install)' "$repo/scripts/ci/windows-machine-adapter-test.ps1"
t_check "windows-machine-adapter-test.ps1 asks for an administrator" grep -q 'refused: not an administrator' "$repo/scripts/ci/windows-machine-adapter-test.ps1"
if command -v pwsh >/dev/null 2>&1; then
  RC=0
  env -u CI -u GITHUB_ACTIONS pwsh -NoProfile -File "$repo/scripts/ci/windows-machine-adapter-test.ps1" >"$OUT" 2>&1 || RC=$?
  t_check "windows-machine-adapter-test.ps1 refuses without CI or -Install: exit 3" rc_is 3
  t_check "windows-machine-adapter-test.ps1 names why" out_has "refused"
fi

# The per-machine suite (M10 step 19) runs its install rows only on CI or with -Install, and only as
# an administrator; it removes what it made and fails on a leftover. Its planted-DLL list is read
# from plant-dll-test.ps1, which prints it with -Describe (the list is in one place).
e2e_machine="$repo/scripts/e2e-windows-machine.ps1"
# shellcheck disable=SC2016  # the script's own PowerShell text, searched literally
t_check "e2e-windows-machine.ps1 gates its install rows on CI or -Install" grep -Fq "if (\$env:CI -eq 'true' -or \$env:LUNEPACK_E2E_INSTALL -eq '1') { \$Install = \$true }" "$e2e_machine"
# shellcheck disable=SC2016
t_check "e2e-windows-machine.ps1 runs the install rows as an administrator only" grep -Fq '$runInstall = $Install -and $isAdmin' "$e2e_machine"
# shellcheck disable=SC2016
t_check "e2e-windows-machine.ps1 fails on a leftover" grep -Fq "FAIL leftovers" "$e2e_machine"
t_check "e2e-windows-machine.ps1 reads the planted list from plant-dll-test.ps1" grep -Fq "plant-dll-test.ps1') -Describe" "$e2e_machine"
if command -v pwsh >/dev/null 2>&1; then
  RC=0
  # shellcheck disable=SC2016  # PowerShell text
  PLANT_SCRIPT="$repo/scripts/ci/plant-dll-test.ps1" pwsh -NoProfile -Command '$d = & $env:PLANT_SCRIPT -Describe; "$($d.Planted.Count) $($d.LoaderFailures.Count) $($d.Content.Length)"' >"$OUT" 2>&1 || RC=$?
  t_check "plant-dll-test.ps1 -Describe prints the list, the failure set and the content" rc_is 0
  t_check "plant-dll-test.ps1 -Describe: twelve names, eight failure codes, eight bytes" out_has "12 8 8"
fi

# The scripts refuse off CI (exit 3) before touching anything: no scratch directory appears.
guard_tmp=$T_TMP/guard-tmp
mkdir -p "$guard_tmp"
for setting in "" "CI=true" "GITHUB_ACTIONS=true"; do
  RC=0
  # shellcheck disable=SC2086  # $setting is empty or one VAR=value word
  env -u CI -u GITHUB_ACTIONS $setting TMPDIR="$guard_tmp" bash "$repo/scripts/ci/os-trust.sh" >"$OUT" 2>&1 || RC=$?
  t_check "os-trust.sh refuses without both CI and GITHUB_ACTIONS (${setting:-neither}): exit 3" rc_is 3
done
t_check "os-trust.sh left nothing behind after refusing" test -z "$(ls -A "$guard_tmp")"
t_check "os-trust.ps1 carries the same guard" grep -q "GITHUB_ACTIONS -ne 'true'" "$repo/scripts/ci/os-trust.ps1"
if command -v pwsh >/dev/null 2>&1; then
  RC=0
  env -u CI -u GITHUB_ACTIONS pwsh -NoProfile -File "$repo/scripts/ci/os-trust.ps1" >"$OUT" 2>&1 || RC=$?
  t_check "os-trust.ps1 refuses off CI: exit 3" rc_is 3
fi

# The throwaway-identity script of the macOS suite (M9 step 9) refuses off CI before it makes a
# directory or touches a keychain, and refuses a bad usage.
if [ "$(uname -s)" = Darwin ]; then
  ident_dir=$T_TMP/ident-never
  RC=0
  env -u CI bash "$repo/scripts/ci/macos-selfsigned.sh" create "$ident_dir" >"$OUT" 2>&1 || RC=$?
  t_check "macos-selfsigned.sh refuses off CI" rc_is 1
  t_check "macos-selfsigned.sh names why" out_has "off CI"
  t_check "macos-selfsigned.sh made nothing when it refused" test ! -e "$ident_dir"
  RC=0
  CI=true bash "$repo/scripts/ci/macos-selfsigned.sh" frobnicate "$ident_dir" >"$OUT" 2>&1 || RC=$?
  t_check "macos-selfsigned.sh: an unknown command is a usage error" rc_is 2
  RC=0
  CI=true bash "$repo/scripts/ci/macos-selfsigned.sh" delete "$T_TMP/guard-tmp" >"$OUT" 2>&1 || RC=$?
  t_check "macos-selfsigned.sh delete refuses a directory it did not make" rc_is 1
  t_check "macos-selfsigned.sh delete left that directory alone" test -d "$T_TMP/guard-tmp"
fi

# Nothing on a runner answers an authorization prompt, so every call of the identity script that
# could wait for one (a trust change, codesign, find-identity) goes through its `bounded`, which
# stops a command that outlives its limit and answers 124 (F13: CI waited 90 minutes in an
# unbounded add-trusted-cert). Pure bash: runs on every OS.
bounded_src=$T_TMP/bounded.sh
sed -n '/^bounded() {/,/^}/p' "$repo/scripts/ci/macos-selfsigned.sh" >"$bounded_src"
t_check "macos-selfsigned.sh defines bounded" grep -q '^bounded() {' "$bounded_src"
RC=0
bounded_start=$SECONDS
bash -c '. "$1"; bounded 1 sleep 30' _ "$bounded_src" >"$OUT" 2>&1 || RC=$?
t_check "bounded stops a command that outlives its limit: 124" rc_is 124
t_check "bounded stopped it within a few seconds" test $((SECONDS - bounded_start)) -lt 10
RC=0
bash -c '. "$1"; bounded 5 sh -c "exit 7"' _ "$bounded_src" >"$OUT" 2>&1 || RC=$?
t_check "bounded passes on the command's own exit status" rc_is 7
# unbounded_prompt_calls prints the code lines of the identity script that change trust, sign or
# list identities without going through bounded.
unbounded_prompt_calls() {
  grep -nE '(add|remove)-trusted-cert|find-identity -p|--sign ' "$repo/scripts/ci/macos-selfsigned.sh" |
    grep -vE '^[0-9]+:[[:space:]]*#' | grep -v 'bounded ' || true
}
t_check "macos-selfsigned.sh: every trust change, codesign and find-identity call is bounded" test -z "$(unbounded_prompt_calls)"

# --- the weekly workflow (M13 step 3) -----------------------------------------------------------
# The fuzz campaign and cargo-deny: read-only token, started by a schedule, by hand and by a push
# (never by a pull request), budgets of 300 seconds on the schedule and 600 otherwise, the corpus
# kept in the Actions cache and the crash inputs as an artifact, the tool installed by an exact version.
weekly=$repo/.github/workflows/weekly.yml

# weekly_ok <file>: prints one line per problem; nonzero when there is any.
weekly_ok() {
  local f=$1 bad=0 perms
  if [ ! -f "$f" ]; then echo "no weekly.yml"; return 1; fi
  # The only permission is `contents: read`, and it is the top-level block.
  perms=$(awk '/^permissions:/ { on = 1; next } on && /^[^ ]/ { exit } on { print }' "$f" | sed 's/[[:space:]]*#.*//; /^[[:space:]]*$/d')
  if [ "$perms" != "  contents: read" ]; then echo "the top-level permissions are not exactly contents: read"; bad=1; fi
  if grep -Eq '^[[:space:]]+permissions:' "$f"; then echo "a job sets its own permissions"; bad=1; fi
  if ! grep -Eq '^  schedule:' "$f"; then echo "no schedule trigger"; bad=1; fi
  if ! grep -Eq '^  workflow_dispatch:' "$f"; then echo "no workflow_dispatch trigger"; bad=1; fi
  if ! grep -Eq '^  push:' "$f"; then echo "no push trigger"; bad=1; fi
  if ! grep -Eq '^      seconds:' "$f" || ! grep -Eq "default: '600'" "$f"; then echo "workflow_dispatch has no seconds input defaulting to 600"; bad=1; fi
  if grep -Eq '^[[:space:]]*pull_request' "$f"; then echo "a pull_request trigger is not allowed"; bad=1; fi
  if ! awk '/^  push:/ { on = 1; next } on && /^  [a-z_]+:/ { exit } on { print }' "$f" | grep -q 'paths:'; then echo "the push trigger is not limited to paths"; bad=1; fi
  if ! grep -q "github.event_name == 'schedule' && '300'" "$f" || ! grep -q "|| '600'" "$f"; then echo "the budget is not 300 on the schedule and 600 otherwise"; bad=1; fi
  if ! grep -q 'scripts/fuzz.sh --list' "$f"; then echo "the target list does not come from scripts/fuzz.sh --list"; bad=1; fi
  if ! grep -q 'actions/cache/restore@' "$f" || ! grep -q 'actions/cache/save@' "$f"; then echo "the corpus is not restored from and saved to the Actions cache"; bad=1; fi
  if ! grep -q 'fuzz-crashes-' "$f"; then echo "the crash inputs are not uploaded"; bad=1; fi
  if ! grep -q 'fuzz-corpus-' "$f"; then echo "the corpus is not uploaded"; bad=1; fi
  if ! grep -Eq 'cargo install --locked --version [0-9]+\.[0-9]+\.[0-9]+ cargo-deny' "$f"; then echo "cargo-deny is not installed at an exact version with --locked"; bad=1; fi
  if ! grep -q 'cargo deny check advisories licenses' "$f"; then echo "cargo deny check advisories licenses is not run"; bad=1; fi
  if grep -Eq 'continue-on-error|--skip|-s none|detect_leaks=0' "$f"; then echo "a failure or a sanitizer is switched off"; bad=1; fi
  return "$bad"
}

RC=0
weekly_ok "$weekly" >"$OUT" 2>&1 || RC=$?
t_check "weekly.yml: read-only token, three triggers and no pull request, budgets, cache, artifacts, cargo-deny" rc_is 0
if [ "$RC" -ne 0 ]; then sed 's/^/    /' "$OUT" >&2; fi
weekly_seed() { # name, sed expression, expected message
  sed "$2" "$weekly" >"$T_TMP/weekly-$1.yml"
  RC=0
  weekly_ok "$T_TMP/weekly-$1.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded weekly.yml ($1) fails" rc_nonzero
  t_check "seeded weekly.yml ($1) reports: $3" out_has "$3"
}
weekly_seed pr 's|^  push:|  pull_request:\n  push:|' "pull_request trigger"
weekly_seed no-schedule 's|^  schedule:|  scheduled:|' "no schedule trigger"
weekly_seed no-dispatch 's|^  workflow_dispatch:|  dispatch:|' "no workflow_dispatch trigger"
weekly_seed no-push 's|^  push:|  pushes:|' "no push trigger"
weekly_seed no-paths 's|^    paths:|    pathz:|' "not limited to paths"
weekly_seed token 's|^  contents: read|  contents: read\n  actions: read|' "not exactly contents: read"
weekly_seed job-permissions 's|^    timeout-minutes: 30|    timeout-minutes: 30\n    permissions:\n      contents: read|' "sets its own permissions"
weekly_seed budget 's|&& '"'"'300'"'"'|\&\& '"'"'900'"'"'|' "300 on the schedule"
weekly_seed no-cache-save 's|actions/cache/save@|actions/cache/other@|' "Actions cache"
weekly_seed no-crash-artifact 's|fuzz-crashes-|fuzz-c-|' "crash inputs"
weekly_seed deny-unpinned 's|--version 0.22.0 ||' "exact version"
weekly_seed continue 's|^    timeout-minutes: 90|    timeout-minutes: 90\n    continue-on-error: true|' "switched off"
weekly_seed no-list 's|scripts/fuzz.sh --list|scripts/fuzz.sh --all|' "fuzz.sh --list"

# Every tracked shell script that a workflow or another script runs by path must be executable
# (git mode 100755): a 100644 one fails with "Permission denied" only in CI. Only the
# scripts/tests/test-*.sh files are exempt, because run.sh runs them through bash.
# modes_not_executable reads `git ls-files -s` lines on stdin and prints the paths that are not 100755.
modes_not_executable() {
  awk '$1 != "100755" { sub(/^[^\t]*\t/, ""); print }' | grep -E '^scripts/.*\.sh$' | grep -Ev '^scripts/tests/test-[^/]*\.sh$' || true
}
mode_fixture=$(printf '100644 0000000000000000000000000000000000000000 0\tscripts/ci/fixture.sh\n100755 0000000000000000000000000000000000000000 0\tscripts/ci/ok.sh\n100644 0000000000000000000000000000000000000000 0\tscripts/tests/test-fixture.sh\n')
t_check "mode check flags a 100644 script and only that" test "$(printf '%s\n' "$mode_fixture" | modes_not_executable)" = "scripts/ci/fixture.sh"
if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  not_exec=$(git -C "$repo" ls-files -s scripts | modes_not_executable)
  [ -z "$not_exec" ] || echo "  not executable (git mode is not 100755): $not_exec" >&2
  t_check "every tracked scripts/**/*.sh (except tests/test-*.sh) has git mode 100755" test -z "$not_exec"
fi

t_finish
