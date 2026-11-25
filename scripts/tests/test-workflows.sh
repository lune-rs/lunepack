#!/usr/bin/env bash
# Lint .github/workflows/*.yml with plain text rules (fail closed: at least one workflow
# must exist). Each rule is also seeded against a bad temp copy to prove it can fail.
#   test-workflows.sh [workflow-dir]     (default: <repo>/.github/workflows)
# Every file in the directory is linted and must end in .yml (GitHub also runs .yaml files).
# Rules per file: a column-0 `permissions:` line; no pull_request_target; no `write`, no `secrets`
# word, no `environment:` key and no name of the project key, except the scoped lines of
# release.yml (M13 step 14: `contents: write` on draft, attach and finalize; the key line and
# `environment: release-signing` on sign); no expression of the event, the ref name, the head ref,
# an input or a secret inside a `run:` script; every `uses:` is ./... or owner/repo[/path]@<40 hex>.
# release.yml has its own rules on top (release_ok), on its jobs and the steps of the job sign.
# bash 3.2 compatible.
# shellcheck disable=SC2016,SC2329 # SC2016: workflow text with literal ${{ }}; SC2329: seed edits run through r
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

# The one line of all workflow files that may name the project key (M13-D35): in release.yml, the
# `env:` of the one `run:` step of the job `sign` (where exactly is release_ok's to check).
KEY_LINE='          LUNEPACK_PROJECT_KEY: ${{ secrets.LUNEPACK_PROJECT_KEY }}'

# line_rules <file>: the per-line rules that know which top-level job a line is in (jobs at two
# spaces under `jobs:`). In release.yml only: `contents: write` as the one line of a job-level
# `permissions:` block of draft, attach or finalize; the key line in the job sign;
# `environment: release-signing` on the job sign. Everywhere else the word `write`, the word
# `secrets` (so `secrets.`, `secrets: inherit`, `toJSON(secrets)` alike), the key's name and an
# `environment:` key fail. Prints one line per violation.
line_rules() {
  local base=${1##*/}
  awk -v base="$base" -v keyline="$KEY_LINE" '
    /^jobs:/ { injobs = 1; job = ""; next }
    /^[^ #]/ { injobs = 0; job = "" }
    injobs && /^  [A-Za-z0-9_-]+:/ { job = $0; sub(/^  /, "", job); sub(/:.*/, "", job) }
    {
      l = tolower($0)
      rel = (base == "release.yml")
      if (l ~ /(^|[^a-z0-9_])write([^a-z0-9_]|$)/ &&
          !(rel && $0 == "      contents: write" && (job == "draft" || job == "attach" || job == "finalize") && prev == "    permissions:"))
        printf "line %d: write permission/word is not allowed here (job %s)\n", NR, (job == "" ? "none" : job)
      if (l ~ /(^|[^a-z0-9_])secrets([^a-z0-9_]|$)/ && !(rel && job == "sign" && $0 == keyline))
        printf "line %d: secrets is not allowed here (job %s)\n", NR, (job == "" ? "none" : job)
      if ($0 ~ /LUNEPACK_PROJECT_KEY/ && !(rel && job == "sign" && $0 == keyline))
        printf "line %d: LUNEPACK_PROJECT_KEY is named outside the key line of the job sign\n", NR
      if (l ~ /(^|[[:space:]-])environment[[:space:]]*:/ && !(rel && job == "sign" && $0 == "    environment: release-signing"))
        printf "line %d: environment: is not allowed here (job %s)\n", NR, (job == "" ? "none" : job)
      if ($0 !~ /^[[:space:]]*(#.*)?$/) prev = $0
    }
  ' "$1"
}

# run_expressions <file>: prints every line of a `run:` script (one line or a block scalar) that holds
# an expression of the event, the ref name, the head ref, an input or a secret.
run_expressions() {
  awk '
    function bad(s) { return s ~ /\$\{\{[^}]*(github\.event|github\.ref_name|github\.head_ref|inputs[.[]|secrets)/ }
    inblock {
      if ($0 ~ /^[[:space:]]*$/) next
      match($0, /^ */)
      if (RLENGTH > keyind) { if (bad($0)) printf "line %d: an expression inside run: %s\n", NR, $0; next }
      inblock = 0
    }
    /^[[:space:]]*(-[[:space:]]+)?run:/ {
      i = index($0, "run:")
      keyind = i - 1
      rest = substr($0, i + 4)
      sub(/^[[:space:]]+/, "", rest)
      if (rest ~ /^[|>][-+0-9]*[[:space:]]*(#.*)?$/) { inblock = 1 }
      else if (bad(rest)) printf "line %d: an expression inside run: %s\n", NR, $0
    }
  ' "$1"
}

# lint_file <file>: prints one line per violation; returns nonzero when there is any.
lint_file() {
  local f=$1 bad=0 rules
  if ! grep -q '^permissions:' "$f"; then echo "no top-level permissions: line"; bad=1; fi
  if grep -qi 'pull_request_target' "$f"; then echo "pull_request_target is not allowed"; bad=1; fi
  rules=$(line_rules "$f")
  if [ -n "$rules" ]; then printf '%s\n' "$rules"; bad=1; fi
  rules=$(run_expressions "$f")
  if [ -n "$rules" ]; then printf '%s\n' "$rules"; bad=1; fi
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

# lint_dir <dir>: lints every regular file in it, whatever its name, and release.yml also with
# release_ok; fails on any entry whose name does not end in .yml (GitHub also runs .yaml files, which
# would escape the rules), when there is no .yml file (fail closed) or when any file has a violation.
lint_dir() {
  local d=$1 f n=0 bad=0
  for f in "$d"/* "$d"/.[!.]*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    case ${f##*/} in
      *.yml) n=$((n + 1)) ;;
      *)
        echo "${f##*/}: not a .yml workflow file (every file here must end in .yml)"
        bad=1
        ;;
    esac
    [ -f "$f" ] || continue
    if ! lint_file "$f" >"$T_TMP/file-out.txt" 2>&1; then
      bad=1
      sed "s|^|${f##*/}: |" "$T_TMP/file-out.txt"
    fi
    if [ "${f##*/}" = release.yml ] && ! release_ok "$f" >"$T_TMP/file-out.txt" 2>&1; then
      bad=1
      sed "s|^|${f##*/}: |" "$T_TMP/file-out.txt"
    fi
  done
  if [ "$n" -eq 0 ]; then echo "no workflow files found in the directory"; return 1; fi
  return "$bad"
}

# job_block <file> <job>: the lines of one top-level job.
job_block() {
  awk -v job="  $2:" '
    $0 == job { on = 1; print; next }
    on && /^  [A-Za-z0-9_-]+:/ { exit }
    on && /^[^ #]/ { exit }
    on { print }
  ' "$1"
}

# step_blocks <file> <job>: the job's steps, one block each, separated by a line "@@"; a step's first
# line has its "- " turned into two spaces, so every step key is at eight spaces. It relies on the
# layout of every workflow here (jobs at two spaces, job keys at four, steps at six, step keys at
# eight, `steps:` the job's last key) and fails, saying why on stdout, on what it cannot place: a tab,
# a flow-style value after steps:, env: or with:, a line in the steps list indented less than eight
# spaces that does not start a step, or a uses:, run: or env: key outside a step.
step_blocks() {
  local block
  block=$(job_block "$1" "$2")
  [ -n "$block" ] || {
    echo "step_blocks: no job $2"
    return 1
  }
  printf '%s\n' "$block" | awk -v job="$2" '
    function fail(m) { print "step_blocks: job " job ": " m; bad = 1; exit 1 }
    NR == 1 { next }
    {
      line = $0
      if (index(line, "\t")) fail("a tab")
      if (line ~ /^[[:space:]]*(#.*)?$/) next
      if (line ~ /^[[:space:]]*(-[[:space:]]+)?(steps|env|with):[[:space:]]*[[{]/) fail("a flow-style value: " line)
      if (!insteps) {
        if (line ~ /^    steps:[[:space:]]*$/) { insteps = 1; next }
        if (line ~ /^[[:space:]]*(-[[:space:]]+)?(uses|run|env):/) fail("a uses:, run: or env: key outside a step: " line)
        next
      }
      if (line ~ /^      - /) {
        n++
        if (n > 1) print "@@"
        sub(/^      - /, "        ", line)
        print line
        next
      }
      if (line ~ /^        / && n > 0) { print line; next }
      fail("a line in the steps list that does not start a step and is indented less than eight spaces: " line)
    }
    END { if (bad) exit 1; if (!insteps || n == 0) { print "step_blocks: job " job ": no steps"; exit 1 } }
  '
}

# nth_step <blocks> <n>: the lines of step n (from 1) of step_blocks' output.
nth_step() {
  printf '%s\n' "$1" | awk -v n="$2" 'BEGIN { b = 1 } $0 == "@@" { b++; next } b == n { print }'
}

# step_count <blocks>: the number of steps in step_blocks' output.
step_count() {
  printf '%s\n' "$1" | awk 'BEGIN { b = 1 } $0 == "@@" { b++ } END { print b }'
}

# step_env <step>: the lines of a step's `env:` mapping (keys at ten spaces), one per line.
step_env() {
  printf '%s\n' "$1" | awk '
    $0 == "        env:" { on = 1; next }
    on && /^          / { print; next }
    on && /^[[:space:]]*(#.*)?$/ { next }
    on { on = 0 }
  '
}

# The release workflow (M13 step 14). The `if:` the privileged jobs carry, and the sign step.
IF_PHASE1="    if: needs.plan.outputs.mode == 'binaries' || needs.plan.outputs.mode == 'rehearsal'"
IF_PHASE2="    if: needs.plan.outputs.mode == 'tag' || needs.plan.outputs.mode == 'rehearsal-finalize'"
SIGN_RUN='        run: scripts/release/sign-list.sh "$LUNEPACK_SIGN_LIST" "$LUNEPACK_SIGN_OUT" "$LUNEPACK_RELEASE_MODE"'
SIGN_ENV="$KEY_LINE
          LUNEPACK_CLI: release-tool/lunepack
          LUNEPACK_SIGN_LIST: release-list/prebuilt-\${{ needs.plan.outputs.version }}.json
          LUNEPACK_SIGN_OUT: release-out/prebuilt-\${{ needs.plan.outputs.version }}.sig.json
          LUNEPACK_RELEASE_MODE: \${{ needs.plan.outputs.mode }}"
SIGN_UPLOAD_PATH='          path: release-out/prebuilt-${{ needs.plan.outputs.version }}.sig.json'

# release_ok <file>: the rules of release.yml beyond lint_file. Prints one line per problem.
release_ok() {
  local f=$1 bad=0 job block blocks n i step uses runs
  problem() {
    echo "$1"
    bad=1
  }
  grep -q 'pull_request' "$f" && problem "a pull_request trigger is not allowed in release.yml"
  grep -Eq '^  workflow_dispatch:' "$f" || problem "no workflow_dispatch trigger"
  grep -Eq '^  push:' "$f" || problem "no push trigger"
  grep -Fxq "      - 'v*'" "$f" || problem "the push trigger has no v* tag filter"
  [ "$(awk '/^permissions:/ { on = 1; next } on && /^[^ ]/ { exit } on { print }' "$f" | sed 's/[[:space:]]*#.*//; /^[[:space:]]*$/d')" = "  contents: read" ] ||
    problem "the top-level permissions are not exactly contents: read"
  [ "$(grep -Eic '(^|[^a-z0-9_])write([^a-z0-9_]|$)' "$f")" -eq 3 ] || problem "release.yml must have exactly three contents: write lines (draft, attach, finalize)"
  grep -Eiq 'id-token|attestations' "$f" && problem "id-token or attestations is not allowed in release.yml"
  grep -q 'actions/cache' "$f" && problem "actions/cache is not allowed in release.yml (no cache feeds a release build)"
  grep -Eq 'runs-on:.*latest|os:.*latest' "$f" && problem "runner images must be named by version, not latest"
  [ "$(grep -c 'LUNEPACK_PROJECT_KEY' "$f")" -eq 1 ] || problem "the project key is not named on exactly one line"
  [ "$(grep -Eic '(^|[^a-z0-9_])secrets([^a-z0-9_]|$)' "$f")" -eq 1 ] || problem "secrets is not on exactly one line"
  if grep -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$f" | grep -Ev '@[0-9a-f]{40} # v[0-9]' | grep -q .; then
    problem "an action without its version in a comment (uses: owner/repo@<40 hex> # v<version>)"
  fi
  for job in plan preflight build build-cli assemble selftest draft sign attach finalize; do
    [ -n "$(job_block "$f" "$job")" ] || problem "no job $job"
  done
  for job in draft sign attach finalize; do
    block=$(job_block "$f" "$job")
    case $job in
      finalize) printf '%s\n' "$block" | grep -Fxq "$IF_PHASE2" || problem "$job has no mode if: (tag or rehearsal-finalize)" ;;
      *) printf '%s\n' "$block" | grep -Fxq "$IF_PHASE1" || problem "$job has no mode if: (binaries or rehearsal)" ;;
    esac
    printf '%s\n' "$block" | grep -Eq 'always\(\)|continue-on-error' && problem "$job uses always() or continue-on-error"
  done
  # Every job splits into steps, and every checkout keeps no credentials.
  while IFS= read -r job; do
    if ! blocks=$(step_blocks "$f" "$job"); then
      printf '%s\n' "$blocks"
      problem "$job: its steps cannot be told apart"
      continue
    fi
    n=$(step_count "$blocks")
    i=1
    while [ "$i" -le "$n" ]; do
      step=$(nth_step "$blocks" "$i")
      if printf '%s\n' "$step" | grep -q '^        uses: actions/checkout@' && ! printf '%s\n' "$step" | grep -Fxq '          persist-credentials: false'; then
        problem "$job: a checkout without persist-credentials: false"
      fi
      # The jobs that run a handed-over file, or hold a write token, download by artifact id: a
      # download by name or pattern takes whatever any job of the run uploaded last under that name.
      case $job in
        sign | attach | finalize)
          if printf '%s\n' "$step" | grep -q '^        uses: actions/download-artifact@'; then
            if printf '%s\n' "$step" | grep -Eq '^          (name|pattern):' ||
              ! printf '%s\n' "$step" | grep -Eq '^          artifact-ids: \$\{\{ needs\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_]+ \}\}(,\$\{\{ needs\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_]+ \}\})*$'; then
              problem "$job: a download-artifact step that is not by artifact-ids: from a job output (a download by name or pattern can be replaced by any job of the run)"
            fi
          fi
          ;;
      esac
      i=$((i + 1))
    done
  done < <(awk '/^jobs:/ { on = 1; next } on && /^[^ #]/ { exit } on && /^  [A-Za-z0-9_-]+:/ { j = $0; sub(/^  /, "", j); sub(/:.*/, "", j); print j }' "$f")
  # preflight holds the key path down before sign may start.
  block=$(job_block "$f" preflight)
  for want in 'bash scripts/tests/test-workflows.sh' 'bash scripts/tests/test-release-scripts.sh' 'scripts/release/check-signing-env.sh'; do
    printf '%s\n' "$block" | grep -Fq "$want" || problem "preflight does not run $want"
  done
  # draft serializes on its concurrency group.
  block=$(job_block "$f" draft)
  printf '%s\n' "$block" | awk '$0 == "    concurrency:" { on = 1; next } on && /^      / { print; next } on { exit }' >"$T_TMP/conc.txt"
  [ "$(cat "$T_TMP/conc.txt")" = "      group: release-draft
      cancel-in-progress: false" ] || problem "draft has no concurrency: block (group release-draft, cancel-in-progress false)"
  # attach comes after sign.
  job_block "$f" attach | grep -Eq '^    needs: \[([^]]*, )?sign(, [^]]*)?\]$' || problem "attach does not need sign"
  # The job sign (M13-D35).
  block=$(job_block "$f" sign)
  printf '%s\n' "$block" | grep -Fxq '    environment: release-signing' || problem "sign has no environment release-signing"
  for want in draft preflight build-cli; do
    printf '%s\n' "$block" | grep -Eq "^    needs: \[([^]]*, )?$want(, [^]]*)?\]$" || problem "sign does not need $want"
  done
  [ "$(printf '%s\n' "$block" | awk '$0 == "    permissions:" { on = 1; next } on && /^      / { print; next } on { exit }')" = "      contents: read" ] ||
    problem "sign has no permissions block with only contents: read"
  if ! blocks=$(step_blocks "$f" sign); then
    problem "sign: its steps cannot be told apart"
  else
    n=$(step_count "$blocks")
    runs=0
    i=1
    while [ "$i" -le "$n" ]; do
      step=$(nth_step "$blocks" "$i")
      uses=$(printf '%s\n' "$step" | grep -c '^        uses:' || true)
      if [ "$(printf '%s\n' "$step" | grep -c '^        run:' || true)" -eq 1 ]; then runs=$((runs + 1)); fi
      if [ "$((uses + $(printf '%s\n' "$step" | grep -c '^        run:' || true)))" -ne 1 ]; then
        problem "sign: step $i does not have exactly one of uses: and run:"
      fi
      if [ "$uses" -eq 1 ] && ! printf '%s\n' "$step" | grep -Eq '^        uses: actions/(checkout|download-artifact|upload-artifact)@'; then
        problem "sign uses an action other than checkout, download-artifact and upload-artifact"
      fi
      if printf '%s\n' "$step" | grep -q '^        run:'; then
        printf '%s\n' "$step" | grep -Fxq "$SIGN_RUN" || problem "sign: the run: step is not the literal command of sign-list.sh"
        [ "$(step_env "$step" | LC_ALL=C sort)" = "$(printf '%s\n' "$SIGN_ENV" | LC_ALL=C sort)" ] ||
          problem "sign: the env: of the run: step is not exactly the five keys"
      elif printf '%s\n' "$step" | grep -q '^        env:'; then
        problem "sign: a step other than the run: step has env:"
      fi
      i=$((i + 1))
    done
    [ "$runs" -eq 1 ] || problem "sign has $runs run: steps, not 1"
    step=$(nth_step "$blocks" 1)
    printf '%s\n' "$step" | grep -q '^        uses: actions/checkout@' || problem "sign: step 1 is not the checkout"
    for i in 2 3; do
      nth_step "$blocks" "$i" | grep -q '^        uses: actions/download-artifact@' || problem "sign: step $i is not a download-artifact"
    done
    nth_step "$blocks" 4 | grep -q '^        run:' || problem "sign: step 4 is not the run: step"
    step=$(nth_step "$blocks" 5)
    printf '%s\n' "$step" | grep -q '^        uses: actions/upload-artifact@' || problem "sign: step 5 is not the upload-artifact"
    printf '%s\n' "$step" | grep -Fxq "$SIGN_UPLOAD_PATH" || problem "sign: the upload path is not the envelope file"
    printf '%s\n' "$step" | grep -Fxq '          if-no-files-found: error' || problem "sign: the upload has no if-no-files-found: error"
    [ "$n" -eq 5 ] || problem "sign has $n steps, not the five in order (checkout, two downloads, run, upload)"
  fi
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
      - run: echo \${{ secrets.TOKEN }}" "secrets"
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

# A workflow under another extension is refused, even one that passes every other rule.
mkdir -p "$T_TMP/yaml-good" "$T_TMP/yaml-bad"
cp "$T_TMP/good.yml" "$T_TMP/yaml-good/good.yml"
cp "$T_TMP/good.yml" "$T_TMP/yaml-good/extra.yaml"
RC=0
lint_dir "$T_TMP/yaml-good" >"$OUT" 2>&1 || RC=$?
t_check "seeded extra.yaml that passes every other rule fails" rc_nonzero
t_check "seeded extra.yaml reports: not a .yml workflow file" out_has "extra.yaml: not a .yml workflow file"
cp "$T_TMP/good.yml" "$T_TMP/yaml-bad/good.yml"
cp "$T_TMP/secrets.yml" "$T_TMP/yaml-bad/bad.yaml"
RC=0
lint_dir "$T_TMP/yaml-bad" >"$OUT" 2>&1 || RC=$?
t_check "seeded .yaml file holding secrets. fails" rc_nonzero
t_check "seeded .yaml file reports its extension" out_has "bad.yaml: not a .yml workflow file"
t_check "seeded .yaml file reports its secrets" out_has "bad.yaml: line"

# --- the release workflow (M13 step 14) ------------------------------------------------------
# Seeded copies of the real release.yml, each linted as release.yml (lint_file and release_ok); each
# must fail for the reason it names.
real_release=$dir/release.yml
SHA=0123456789abcdef0123456789abcdef01234567
if [ ! -f "$real_release" ]; then
  t_fail "no release.yml in the workflow directory"
else
  # in_job_sub <job> <regex> <line>: the first line of the job matching the regex replaced (awk -v
  # turns \n into a line break and \t into a tab).
  in_job_sub() {
    awk -v job="  $1:" -v re="$2" -v rep="$3" '
      /^  [A-Za-z0-9_-]+:/ || /^[^ #]/ { on = ($0 == job) }
      on && !done && $0 ~ re { print rep; done = 1; next }
      { print }
      END { if (!done) exit 1 }
    ' "$4"
  }
  # in_job_ins <job> <regex> <text>: the text inserted after the first line of the job matching the regex.
  in_job_ins() {
    awk -v job="  $1:" -v re="$2" -v text="$3" '
      /^  [A-Za-z0-9_-]+:/ || /^[^ #]/ { on = ($0 == job) }
      { print }
      on && !done && $0 ~ re { print text; done = 1 }
      END { if (!done) exit 1 }
    ' "$4"
  }
  # in_job_del <job> <regex>: the first line of the job matching the regex removed.
  in_job_del() {
    awk -v job="  $1:" -v re="$2" '
      /^  [A-Za-z0-9_-]+:/ || /^[^ #]/ { on = ($0 == job) }
      on && !done && $0 ~ re { done = 1; next }
      { print }
      END { if (!done) exit 1 }
    ' "$3"
  }
  # rseed <name> <expected message>: lints $T_TMP/r.yml as release.yml in a directory of its own.
  rseed() {
    local d=$T_TMP/rseed-$1
    mkdir -p "$d"
    cp "$T_TMP/r.yml" "$d/release.yml"
    RC=0
    lint_dir "$d" >"$OUT" 2>&1 || RC=$?
    t_check "seeded release.yml ($1) fails" rc_nonzero
    t_check "seeded release.yml ($1) reports: $2" out_has "$2"
    if ! out_has "$2"; then sed 's/^/    /' "$OUT" >&2; fi
  }
  # r <command...>: the command's output (an edit of the real file) becomes $T_TMP/r.yml; an edit
  # that matched nothing is a broken seed, which fails the test.
  r() {
    if ! "$@" >"$T_TMP/r.yml"; then t_fail "a seed edit did not apply: $*"; fi
  }
  key_re='^          LUNEPACK_PROJECT_KEY:'

  mkdir -p "$T_TMP/rseed-control"
  cp "$real_release" "$T_TMP/rseed-control/release.yml"
  RC=0
  lint_dir "$T_TMP/rseed-control" >"$OUT" 2>&1 || RC=$?
  t_check "a copy of the real release.yml passes (control)" rc_is 0

  r awk 'p { $0 = "  contents: write"; p = 0 } /^permissions:/ { p = 1 } { print }' "$real_release"
  rseed top-write "write permission/word is not allowed here (job none)"
  r awk '/^permissions:/ { print "permissions: write-all"; skip = 1; next } skip { skip = 0; next } { print }' "$real_release"
  rseed write-all "write permission/word is not allowed here (job none)"
  r in_job_ins selftest '^    timeout-minutes:' '    permissions:\n      contents: write' "$real_release"
  rseed fourth-write "write permission/word is not allowed here (job selftest)"
  r in_job_ins draft '^      contents: write$' '      id-token: write' "$real_release"
  rseed id-token "id-token or attestations is not allowed"
  r in_job_del attach '^    if: ' "$real_release"
  rseed attach-no-if "attach has no mode if:"
  r in_job_sub finalize '^    if: ' "    if: needs.plan.outputs.mode != 'dry-run'" "$real_release"
  rseed finalize-other-if "finalize has no mode if:"
  r in_job_ins draft '^    timeout-minutes:' '    continue-on-error: true' "$real_release"
  rseed draft-continue "draft uses always() or continue-on-error"
  r in_job_del sign '^    environment:' "$real_release"
  rseed sign-no-environment "sign has no environment release-signing"
  r in_job_sub sign '^    environment:' '    environment: release' "$real_release"
  rseed sign-other-environment "environment: is not allowed here (job sign)"
  r in_job_ins draft '^    timeout-minutes:' '    environment: release-signing' "$real_release"
  rseed draft-environment "environment: is not allowed here (job draft)"
  r in_job_sub sign '^      contents: read$' '      contents: write' "$real_release"
  rseed sign-write "write permission/word is not allowed here (job sign)"
  in_job_del sign '^    permissions:' "$real_release" >"$T_TMP/r1.yml" || t_fail "seed edit: sign permissions"
  r in_job_del sign '^      contents: read$' "$T_TMP/r1.yml"
  rseed sign-no-permissions "sign has no permissions block with only contents: read"
  r in_job_ins assemble '^          LUNEPACK_RELEASE_MODE:' '          OTHER: ${{ secrets.OTHER }}' "$real_release"
  rseed second-secrets "secrets is not allowed here (job assemble)"
  in_job_del sign "$key_re" "$real_release" >"$T_TMP/r1.yml" || t_fail "seed edit: key line"
  r in_job_ins sign '^    timeout-minutes:' "    env:\n      LUNEPACK_PROJECT_KEY: \${{ secrets.LUNEPACK_PROJECT_KEY }}" "$T_TMP/r1.yml"
  rseed key-at-job-level "secrets is not allowed here (job sign)"
  r in_job_ins assemble '^          LUNEPACK_RELEASE_MODE:' "$KEY_LINE" "$T_TMP/r1.yml"
  rseed key-in-another-job "secrets is not allowed here (job assemble)"
  r in_job_ins build-cli '^    timeout-minutes:' '    secrets: inherit' "$real_release"
  rseed secrets-inherit "secrets is not allowed here (job build-cli)"
  r in_job_sub assemble '^        run: scripts/release/assemble.sh' '        run: echo "${{ toJSON(secrets) }}"' "$real_release"
  rseed tojson-secrets "secrets is not allowed here (job assemble)"
  r in_job_ins sign '^          path: release-tool$' "      - uses: actions/setup-node@$SHA # v4.0.0" "$real_release"
  rseed fourth-action "sign uses an action other than checkout, download-artifact and upload-artifact"
  r in_job_sub sign '^      - uses: actions/upload-artifact@' "      - run: echo second\n      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2" "$real_release"
  rseed second-run "sign has 2 run: steps, not 1"
  r in_job_ins build '^          persist-credentials: false' "      - uses: actions/cache@$SHA # v4.0.0\n        with:\n          path: target\n          key: release" "$real_release"
  rseed cache "actions/cache is not allowed in release.yml"
  r awk '{ print } /^on:/ { print "  pull_request:" }' "$real_release"
  rseed pull-request "a pull_request trigger is not allowed in release.yml"
  r in_job_sub sign '^          artifact-ids: .*outputs.id_linux_x86_64' '          name: release-cli-linux-x86_64' "$real_release"
  rseed sign-download-by-name "sign: a download-artifact step that is not by artifact-ids"
  r in_job_sub attach '^          artifact-ids: .*outputs.envelope_id' '          name: release-envelope' "$real_release"
  rseed attach-download-by-name "attach: a download-artifact step that is not by artifact-ids"
  r in_job_sub finalize '^          artifact-ids: ' '          pattern: release-cli-*' "$real_release"
  rseed finalize-download-by-pattern "finalize: a download-artifact step that is not by artifact-ids"
  r in_job_sub attach '^          artifact-ids: .*outputs.id_linux_x86_64' '          artifact-ids: 123' "$real_release"
  rseed attach-literal-id "attach: a download-artifact step that is not by artifact-ids"
  r in_job_sub assemble '^        run: scripts/release/assemble.sh' '        run: scripts/release/assemble.sh "${{ inputs.mode }}" a b' "$real_release"
  rseed run-expression "an expression inside run:"
  r in_job_ins sign '^          persist-credentials: false' "        env:\n$KEY_LINE" "$T_TMP/r1.yml"
  rseed key-in-checkout "sign: a step other than the run: step has env:"
  r in_job_ins sign '^          if-no-files-found: error' "        env:\n$KEY_LINE" "$T_TMP/r1.yml"
  rseed key-in-upload "sign: a step other than the run: step has env:"
  r in_job_sub sign '^      - uses: actions/upload-artifact@' "      - run: echo second\n        env:\n$KEY_LINE\n      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2" "$real_release"
  rseed key-in-second-run "sign has 2 run: steps, not 1"
  t_check "seeded release.yml (key-in-second-run) reports the key named twice" out_has "the project key is not named on exactly one line"
  r in_job_ins sign '^          LUNEPACK_RELEASE_MODE:' '          EXTRA: x' "$real_release"
  rseed sixth-env-key "sign: the env: of the run: step is not exactly the five keys"
  r in_job_sub sign '^      - run: scripts/release/sign-list.sh' '      - run: scripts/release/sign-list.sh "$LUNEPACK_SIGN_LIST" "$LUNEPACK_SIGN_OUT" "${{ needs.plan.outputs.mode }}"' "$real_release"
  rseed mode-in-sign-run "sign: the run: step is not the literal command of sign-list.sh"
  r in_job_sub sign '^          path: release-out/' '          path: .' "$real_release"
  rseed upload-dot "sign: the upload path is not the envelope file"
  r in_job_sub sign '^    timeout-minutes:' '    timeout-minutes:\t15' "$real_release"
  rseed tab "step_blocks: job sign: a tab"
  r in_job_sub sign '^    steps:$' '    steps: [ ]' "$real_release"
  rseed flow-steps "step_blocks: job sign: a flow-style value"
  in_job_del draft '^    concurrency:' "$real_release" >"$T_TMP/r1.yml" || t_fail "seed edit: draft concurrency"
  in_job_del draft '^      group: release-draft' "$T_TMP/r1.yml" >"$T_TMP/r2.yml" || t_fail "seed edit: draft group"
  r in_job_del draft '^      cancel-in-progress: false' "$T_TMP/r2.yml"
  rseed draft-no-concurrency "draft has no concurrency: block"
  r in_job_sub sign '^    needs: ' '    needs: [plan, draft, build-cli]' "$real_release"
  rseed sign-without-preflight "sign does not need preflight"
  r in_job_del preflight 'bash scripts/tests/test-release-scripts.sh' "$real_release"
  rseed preflight-no-fixtures "preflight does not run bash scripts/tests/test-release-scripts.sh"
  r in_job_sub plan '^          persist-credentials: false' '          fetch-depth: 1' "$real_release"
  rseed checkout-credentials "plan: a checkout without persist-credentials: false"
  r in_job_sub plan '^    runs-on:' '    runs-on: ubuntu-latest' "$real_release"
  rseed latest-image "runner images must be named by version"
  r in_job_sub plan '^      - uses: actions/checkout@' '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' "$real_release"
  rseed no-version-comment "an action without its version in a comment"

  # Seeds against ci.yml: a contents: write line and a secrets. reference fail there.
  mkdir -p "$T_TMP/ci-seed"
  if [ -f "$dir/ci.yml" ]; then
    in_job_ins gate '^    runs-on:' '    permissions:\n      contents: write' "$dir/ci.yml" >"$T_TMP/ci-seed/ci.yml" || t_fail "seed edit: ci.yml write"
    RC=0
    lint_dir "$T_TMP/ci-seed" >"$OUT" 2>&1 || RC=$?
    t_check "seeded ci.yml with the allowed release line fails" rc_nonzero
    t_check "seeded ci.yml with the allowed release line reports write" out_has "write permission/word is not allowed here (job gate)"
    in_job_ins gate "^          LUNEPACK_REQUIRE_GITLEAKS:" '          T: ${{ secrets.T }}' "$dir/ci.yml" >"$T_TMP/ci-seed/ci.yml" || t_fail "seed edit: ci.yml secrets"
    RC=0
    lint_dir "$T_TMP/ci-seed" >"$OUT" 2>&1 || RC=$?
    t_check "seeded ci.yml with a secrets. reference fails" rc_nonzero
    t_check "seeded ci.yml with a secrets. reference reports it" out_has "secrets is not allowed here (job gate)"
    cp "$real_release" "$T_TMP/ci-seed/ci.yml"
    RC=0
    lint_dir "$T_TMP/ci-seed" >"$OUT" 2>&1 || RC=$?
    t_check "release.yml's content under another name fails (its exceptions are release.yml's only)" rc_nonzero
    t_check "and reports the key line" out_has "LUNEPACK_PROJECT_KEY is named outside"
  fi

  # step_blocks splits the real sign job into its five steps.
  RC=0
  sign_steps=$(step_blocks "$real_release" sign) || RC=$?
  t_check "step_blocks splits the real sign job" rc_is 0
  t_check "into five steps" test "$(step_count "$sign_steps")" -eq 5
  t_check "the fourth is the run: step" test "$(nth_step "$sign_steps" 4 | head -n 1)" = "$SIGN_RUN"
fi

# --- the os-trust job (M4 step 14) --------------------------------------------------------
# A regression check on the real adapter: it must be a required job with a time bound, and its
# scripts must refuse to run off CI (they change the OS trust store and proxy settings).
repo=$(cd "$here/../.." && pwd)
ci=$repo/.github/workflows/ci.yml

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

# --- the .NET example in the Linux end-to-end job (M13 step 7) ------------------------------
# The job installs the SDK that examples/dotnet/global.json names (an action pinned to a commit, which
# the lint above already requires), and no workflow sets the LUNEPACK_E2E_DOTNET=0 opt-out.
e2e_linux_dotnet_ok() {
  local block bad=0 job
  # The Linux job and the two Windows jobs (M13 step 9) install the same pinned SDK.
  for job in e2e-linux e2e-windows e2e-windows-defender; do
    block=$(job_block "$1" "$job")
    if [ -z "$block" ]; then echo "no $job job"; bad=1; continue; fi
    if ! printf '%s\n' "$block" | grep -Eq '^ *- uses: actions/setup-dotnet@[0-9a-f]{40}'; then echo "$job does not install .NET with a pinned setup-dotnet"; bad=1; fi
    if ! printf '%s\n' "$block" | grep -Fq 'global-json-file: examples/dotnet/global.json'; then echo "$job does not read examples/dotnet/global.json"; bad=1; fi
  done
  if grep -v '^ *#' "$1" | grep -q 'LUNEPACK_E2E_DOTNET:\|LUNEPACK_E2E_DOTNET='; then echo "the workflow sets LUNEPACK_E2E_DOTNET (the opt-out)"; bad=1; fi
  return "$bad"
}

if [ -f "$ci" ]; then
  RC=0
  e2e_linux_dotnet_ok "$ci" >"$OUT" 2>&1 || RC=$?
  t_check "ci.yml's e2e-linux and Windows e2e jobs install the pinned .NET SDK and never opt out" rc_is 0
  if [ "$RC" -ne 0 ]; then sed 's/^/    /' "$OUT" >&2; fi
  grep -v 'setup-dotnet@' "$ci" >"$T_TMP/no-dotnet.yml" || true
  RC=0
  e2e_linux_dotnet_ok "$T_TMP/no-dotnet.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded e2e-linux without setup-dotnet fails" rc_nonzero
  t_check "seeded missing setup-dotnet reports why" out_has "setup-dotnet"
  # Only the Windows Defender job loses its setup-dotnet: it is named.
  awk '/^  e2e-windows-defender:/ { on = 1 } on && /setup-dotnet@/ { skip = 3 } skip > 0 { skip--; next } { print }' "$ci" >"$T_TMP/no-dotnet-defender.yml"
  RC=0
  e2e_linux_dotnet_ok "$T_TMP/no-dotnet-defender.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded Defender job without setup-dotnet fails" rc_nonzero
  t_check "and names the Defender job" out_has "e2e-windows-defender does not install"
  sed 's|^          LUNEPACK_E2E_REQUIRE: .1.$|&\n          LUNEPACK_E2E_DOTNET: "0"|' "$ci" >"$T_TMP/opt-out.yml"
  RC=0
  e2e_linux_dotnet_ok "$T_TMP/opt-out.yml" >"$OUT" 2>&1 || RC=$?
  t_check "seeded opt-out in a workflow fails" rc_nonzero
  t_check "seeded opt-out reports why" out_has "opt-out"
  RC=0
  e2e_linux_dotnet_ok "$T_TMP/good.yml" >"$OUT" 2>&1 || RC=$?
  t_check "a file with no e2e jobs fails" rc_nonzero
fi

t_finish
