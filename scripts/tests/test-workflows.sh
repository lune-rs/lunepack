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
  RC=0
  e2e_windows_jobs_ok "$T_TMP/good.yml" >"$OUT" 2>&1 || RC=$?
  t_check "a file with no Windows e2e jobs fails" rc_nonzero
fi
# --- the macOS end-to-end job (M8 step 11) -----------------------------------------------------
# Required (no continue-on-error), time-bounded, on a macOS runner, runs the suite with --ci, and
# uploads the instrument records whatever the suite did.
e2e_macos_job_ok() {
  local block bad=0
  block=$(job_block "$1" e2e-macos)
  if [ -z "$block" ]; then echo "no e2e-macos job"; return 1; fi
  if ! printf '%s\n' "$block" | grep -q 'timeout-minutes:'; then echo "e2e-macos has no timeout-minutes"; bad=1; fi
  if printf '%s\n' "$block" | grep -q 'continue-on-error'; then echo "e2e-macos must not be continue-on-error"; bad=1; fi
  if ! printf '%s\n' "$block" | grep -q 'runs-on: macos-latest'; then echo "e2e-macos does not run on macos-latest"; bad=1; fi
  if ! printf '%s\n' "$block" | grep -q 'scripts/e2e-macos.sh --ci'; then echo "e2e-macos does not run e2e-macos.sh --ci"; bad=1; fi
  if ! printf '%s\n' "$block" | grep -q 'actions/upload-artifact@'; then echo "e2e-macos does not upload the instrument records"; bad=1; fi
  if ! printf '%s\n' "$block" | grep -q 'if: always()'; then echo "e2e-macos's records are not kept after a failure"; bad=1; fi
  return "$bad"
}

if [ -f "$ci" ]; then
  RC=0
  e2e_macos_job_ok "$ci" >"$OUT" 2>&1 || RC=$?
  t_check "ci.yml has the e2e-macos job, required and time-bounded" rc_is 0
  if [ "$RC" -ne 0 ]; then sed 's/^/    /' "$OUT" >&2; fi
  sed 's|^  e2e-macos:|  e2e-macos:\n    continue-on-error: true|' "$ci" >"$T_TMP/macos-coe.yml"
  RC=0
  e2e_macos_job_ok "$T_TMP/macos-coe.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded continue-on-error on e2e-macos fails" rc_nonzero
  t_check "seeded continue-on-error on e2e-macos reports why" out_has "continue-on-error"
  sed 's|scripts/e2e-macos.sh --ci|scripts/e2e-macos.sh|' "$ci" >"$T_TMP/macos-noci.yml"
  RC=0
  e2e_macos_job_ok "$T_TMP/macos-noci.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded e2e-macos without --ci fails" rc_nonzero
  RC=0
  e2e_macos_job_ok "$T_TMP/good.yml" >"$OUT" 2>&1 || RC=$?
  t_check "a file with no e2e-macos job fails" rc_nonzero
fi

t_check "defender-on.ps1 refuses off GitHub Actions" grep -q "GITHUB_ACTIONS -ne 'true'" "$repo/scripts/ci/defender-on.ps1"
if command -v pwsh >/dev/null 2>&1; then
  RC=0
  env -u CI -u GITHUB_ACTIONS pwsh -NoProfile -File "$repo/scripts/ci/defender-on.ps1" >"$OUT" 2>&1 || RC=$?
  t_check "defender-on.ps1 refuses off CI: exit 3" rc_is 3
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

t_finish
