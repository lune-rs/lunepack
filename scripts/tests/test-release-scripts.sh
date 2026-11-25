#!/usr/bin/env bash
# Tests for scripts/release/*.sh (M13 step 14): mode.sh, assemble.sh, sign-list.sh,
# check-signing-env.sh, pin.sh and verify-pins.sh, on fixtures in temporary git repositories.
#
# - A recording stand-in for `gh` is first on PATH: `gh api` answers from the case's files,
#   `gh release download` copies from a directory per release; every call is logged.
# - The workspace's real `lunepack` CLI (built with `cargo build --locked -p lunepack-cli`; never
#   skipped) sits behind a wrapper named by LUNEPACK_CLI that adds `--trusted-key <the case's public
#   key>` to `prebuilt sign` and `prebuilt verify` (the test binary has no built-in key) and answers
#   `prebuilt list --json` from the case's committed files, as a CLI built with that key would.
# - Keys are throwaway keys made here by `lunepack keys gen`, under an extension of their own.
# Nothing here reaches GitHub, a real key or the network.
# shellcheck disable=SC2016,SC2034 # SC2016: stand-in bodies are scripts; SC2034: RC is read by lib.sh
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"
# shellcheck source=scripts/release/lib.sh
. "$repo/scripts/release/lib.sh"

t_init
command -v jq >/dev/null 2>&1 || {
  t_fail "jq is not on PATH"
  t_finish
}

# --- the real CLI, the version, the throwaway keys ------------------------------------------
(cd "$repo" && cargo build --quiet --locked -p lunepack-cli) || {
  t_fail "cargo build -p lunepack-cli failed"
  t_finish
}
REAL_CLI=${CARGO_TARGET_DIR:-$repo/target}/debug/lunepack
[ -x "$REAL_CLI" ] || {
  t_fail "no lunepack binary after the build"
  t_finish
}
V=$(cd "$repo" && rel_version)

mkdir -p "$T_TMP/keys"
keygen() { # name -> prints the public key; the key file is $T_TMP/keys/<name>.lpk
  "$REAL_CLI" keys gen "$T_TMP/keys/$1.lpk" 2>/dev/null | sed -n 's/^public: //p'
}
PUB1=$(keygen k1)
PUB2=$(keygen k2)
[ -n "$PUB1" ] && [ -n "$PUB2" ] || {
  t_fail "keys gen printed no public key"
  t_finish
}
KEY1=$(<"$T_TMP/keys/k1.lpk")
KEY2=$(<"$T_TMP/keys/k2.lpk")
# The base64 body of each key (the lines between the PEM armour), to prove no output carries it.
key_body() {
  local line body=
  while IFS= read -r line; do
    case $line in
      -----*) ;;
      *) body=$body$line ;;
    esac
  done <"$1"
  printf '%s' "$body"
}
BODY1=$(key_body "$T_TMP/keys/k1.lpk")
BODY2=$(key_body "$T_TMP/keys/k2.lpk")

# --- the stand-ins ------------------------------------------------------------------------------
mkdir -p "$T_TMP/bin"
GH_LOG=$T_TMP/gh.log
GH_ALL_LOG=$T_TMP/gh-all.log
: >"$GH_LOG"
: >"$GH_ALL_LOG"
cat >"$T_TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
printf '%s\n' "$*" >>"$GH_ALL_LOG"
case ${1:-} in
  api)
    key=$(printf '%s' "$2" | tr '/' '_')
    status=200
    if [ -f "$GH_FIX/$key.status" ]; then status=$(cat "$GH_FIX/$key.status"); fi
    if [ "$status" != 200 ] || [ ! -f "$GH_FIX/$key.json" ]; then
      echo "gh: HTTP ${status} (stand-in)" >&2
      exit 1
    fi
    cat "$GH_FIX/$key.json"
    ;;
  release)
    [ "${2:-}" = download ] || exit 1
    tag=$3
    shift 3
    pats=()
    dir=.
    while [ "$#" -gt 0 ]; do
      case $1 in
        --pattern) pats+=("$2"); shift 2 ;;
        --dir) dir=$2; shift 2 ;;
        *) exit 1 ;;
      esac
    done
    src=$GH_RELEASES/$tag
    [ -d "$src" ] || { echo "release not found (stand-in)" >&2; exit 1; }
    if [ "${#pats[@]}" -eq 0 ]; then
      cp "$src"/* "$dir"/
    else
      for p in "${pats[@]}"; do
        if [ -f "$src/$p" ]; then cp "$src/$p" "$dir/"; fi
      done
    fi
    ;;
  *)
    echo "gh stand-in: unsupported call" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$T_TMP/bin/gh"
export GH_LOG GH_ALL_LOG
export PATH="$T_TMP/bin:$PATH"

WRAP=$T_TMP/wrap/lunepack
mkdir -p "$T_TMP/wrap"
cat >"$WRAP" <<EOF
#!/usr/bin/env bash
# The real CLI with the case's public key as the trusted key of sign and verify; prebuilt list
# answers from the committed files of the work tree, as a CLI with that key built in would.
real='$REAL_CLI'
EOF
cat >>"$WRAP" <<'EOF'
if [ "${1:-}" = prebuilt ] && { [ "${2:-}" = sign ] || [ "${2:-}" = verify ]; }; then
  exec "$real" "$@" --trusted-key "$WRAP_PUB"
fi
if [ "${1:-}" = prebuilt ] && [ "${2:-}" = list ]; then
  top=$(git rev-parse --show-toplevel) || exit 1
  t=$top/crates/lunepack-cli/prebuilt.json
  s=$top/crates/lunepack-cli/prebuilt.sig.json
  if [ ! -s "$t" ] && [ ! -s "$s" ]; then
    echo '{"binaries":[],"list":null,"reason":null,"roots":[],"state":"none"}'
    exit 0
  fi
  v=$("$real" prebuilt verify --list "$t" --sig "$s" --trusted-key "$WRAP_PUB" --allow-rehearsal --json) || exit 1
  own=$("$real" --version)
  printf '%s\n' "$v" | jq -c --arg own "${own#lunepack }" '{state: (if .version != $own then "other-version" elif .rehearsal then "rehearsal" else "pinned" end), reason: null, roots: [], list: {version, source_commit, rehearsal}, binaries}'
  exit 0
fi
exec "$real" "$@"
EOF
chmod +x "$WRAP"
export WRAP_PUB=$PUB1

ALL=$T_TMP/all-output.txt
: >"$ALL"
# run_in <dir> <command...>: run_cmd in a directory, with every output kept for the key assertion.
run_in() {
  local d=$1
  shift
  RC=0
  (cd "$d" && "$@") >"$OUT" 2>&1 || RC=$?
  cat "$OUT" >>"$ALL"
}

# --- fixtures -------------------------------------------------------------------------------------
# make_work <name>: a git repository shaped like the workspace (the package lunepack-cli at version
# $V, the release scripts, the notices, the two empty pin files) with a bare origin holding main.
# Prints its path.
make_work() {
  local w=$T_TMP/$1 o=$T_TMP/$1-origin.git
  rm -rf "$w" "$o"
  mkdir -p "$w/crates/lunepack-cli/src" "$w/scripts/release"
  cp "$repo/rust-toolchain.toml" "$w/"
  printf '[workspace]\nmembers = ["crates/lunepack-cli"]\nresolver = "2"\n' >"$w/Cargo.toml"
  printf '[package]\nname = "lunepack-cli"\nversion = "%s"\nedition = "2021"\npublish = false\n' "$V" >"$w/crates/lunepack-cli/Cargo.toml"
  : >"$w/crates/lunepack-cli/src/lib.rs"
  echo "// key sets: none" >"$w/crates/lunepack-cli/src/project_key.rs"
  : >"$w/crates/lunepack-cli/prebuilt.json"
  : >"$w/crates/lunepack-cli/prebuilt.sig.json"
  echo "third-party notices (fixture)" >"$w/crates/lunepack-cli/THIRD-PARTY-NOTICES.txt"
  cp "$repo"/scripts/release/*.sh "$w/scripts/release/"
  (
    cd "$w"
    g init -q -b main
    g add -A
    g commit -q -m "A"
    g init -q --bare "$o"
    g remote add origin "$o"
    g push -q origin main
  ) >/dev/null
  printf '%s\n' "$w"
}

# make_bins <dir> [version]: the 20 files of the release matrix, small and distinct.
make_bins() {
  local d=$1 v=${2:-$V} k t
  mkdir -p "$d"
  rel_matrix | while read -r k t; do
    printf 'fixture %s %s %s\n' "$k" "$t" "$v" >"$d/$(rel_asset "$k" "$v" "$t")"
  done
}

# phase1 <work> <mode> <draft-tag>: assemble, sign-list and attach's verification into a draft
# directory $GH_RELEASES/<draft-tag>, as the workflow does. Prints nothing; fails on any error.
phase1() {
  local w=$1 mode=$2 tag=$3 out=$T_TMP/$2-assets sig=$T_TMP/$2-sig
  rm -rf "$out" "$sig" "$T_TMP/$2-bin" "${GH_RELEASES:?}/$tag"
  make_bins "$T_TMP/$2-bin"
  (cd "$w" && scripts/release/assemble.sh "$mode" "$T_TMP/$2-bin" "$out") >>"$ALL" 2>&1 || return 1
  (cd "$w" && LUNEPACK_PROJECT_KEY=$KEY1 LUNEPACK_CLI=$WRAP scripts/release/sign-list.sh "$out/prebuilt-$V.json" "$sig/prebuilt-$V.sig.json" "$mode") >>"$ALL" 2>&1 || return 1
  local allow=()
  if [ "$mode" = rehearsal ]; then allow=(--allow-rehearsal); fi
  "$WRAP" prebuilt verify --list "$out/prebuilt-$V.json" --sig "$sig/prebuilt-$V.sig.json" --dir "$out" --all ${allow[@]+"${allow[@]}"} >>"$ALL" 2>&1 || return 1
  mkdir -p "$GH_RELEASES/$tag"
  cp "$out"/* "$sig/prebuilt-$V.sig.json" "$GH_RELEASES/$tag/"
}

export GH_RELEASES=$T_TMP/releases
export GH_FIX=$T_TMP/ghfix
mkdir -p "$GH_RELEASES" "$GH_FIX"

# --- mode.sh --------------------------------------------------------------------------------------
W=$(make_work mode)
mode_case() { # label, expected rc, expected text, then VAR=value...
  local label=$1 rc=$2 text=$3
  shift 3
  run_in "$W" env -u GITHUB_EVENT_NAME -u GITHUB_REF -u LUNEPACK_INPUT_MODE "$@" scripts/release/mode.sh
  t_check "mode.sh: $label (exit $rc)" rc_is "$rc"
  t_check "mode.sh: $label says $text" out_has "$text"
}
mode_case "the tag v<version>" 0 "mode=tag" GITHUB_EVENT_NAME=push "GITHUB_REF=refs/tags/v$V"
t_check "mode.sh prints the version" out_has "version=$V"
t_check "mode.sh prints exactly two lines" test "$(wc -l <"$OUT" | tr -d ' ')" -eq 2
mode_case "another tag" 1 "the tag is not v$V" GITHUB_EVENT_NAME=push GITHUB_REF=refs/tags/v9.9.9
mode_case "a branch push" 0 "mode=dry-run" GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/orch/x
mode_case "a push with an input" 1 "a push has no mode input" GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main LUNEPACK_INPUT_MODE=binaries
mode_case "dispatch dry-run on a branch" 0 "mode=dry-run" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/orch/x LUNEPACK_INPUT_MODE=dry-run
mode_case "dispatch binaries on main" 0 "mode=binaries" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main LUNEPACK_INPUT_MODE=binaries
mode_case "dispatch binaries off main" 1 "runs on refs/heads/main only" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/orch/x LUNEPACK_INPUT_MODE=binaries
mode_case "dispatch rehearsal on main" 0 "mode=rehearsal" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main LUNEPACK_INPUT_MODE=rehearsal
mode_case "dispatch rehearsal off main" 1 "runs on refs/heads/main only" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/release-rehearsal LUNEPACK_INPUT_MODE=rehearsal
mode_case "dispatch rehearsal-finalize on release-rehearsal" 0 "mode=rehearsal-finalize" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/release-rehearsal LUNEPACK_INPUT_MODE=rehearsal-finalize
mode_case "dispatch rehearsal-finalize on main" 1 "refs/heads/release-rehearsal only" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main LUNEPACK_INPUT_MODE=rehearsal-finalize
mode_case "dispatch tag" 1 "unrecognised mode input" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main LUNEPACK_INPUT_MODE=tag
mode_case "dispatch with no input" 1 "unrecognised mode input" GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main
mode_case "dispatch on a tag" 1 "a dispatch runs on a branch only" GITHUB_EVENT_NAME=workflow_dispatch "GITHUB_REF=refs/tags/v$V" LUNEPACK_INPUT_MODE=dry-run
mode_case "a pull request" 1 "unrecognised event" GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/merge
mode_case "no event" 1 "GITHUB_EVENT_NAME is not set" GITHUB_REF=refs/heads/main

# --- assemble.sh ----------------------------------------------------------------------------------
W=$(make_work assemble)
make_bins "$T_TMP/bins"
for m in binaries rehearsal dry-run; do
  rm -rf "$T_TMP/asm-$m"
  run_in "$W" scripts/release/assemble.sh "$m" "$T_TMP/bins" "$T_TMP/asm-$m"
  t_check "assemble.sh $m passes" rc_is 0
  run_in "$W" "$REAL_CLI" prebuilt check --list "$T_TMP/asm-$m/prebuilt-$V.json" --json
  t_check "the CLI's parser accepts what assemble.sh wrote ($m)" rc_is 0
  if [ "$m" = binaries ]; then want=false; else want=true; fi
  t_check "the list of mode $m has rehearsal $want" test "$(jq -r '.rehearsal' "$OUT")" = "$want"
  t_check "the list of mode $m has 20 rows" test "$(jq -r '.binaries | length' "$OUT")" -eq 20
  t_check "the list of mode $m names HEAD" test "$(jq -r '.source_commit' "$OUT")" = "$(g -C "$W" rev-parse HEAD)"
done
t_check "the list ends in one LF" test "$(tail -c 1 "$T_TMP/asm-binaries/prebuilt-$V.json" | od -An -tx1 | tr -d ' ')" = 0a
t_check "the list has no CR" test "$(tr -cd '\r' <"$T_TMP/asm-binaries/prebuilt-$V.json" | wc -c | tr -d ' ')" -eq 0
t_check "SHA256SUMS lists 22 files (20 binaries, the list, the notices; not itself)" test "$(wc -l <"$T_TMP/asm-binaries/SHA256SUMS" | tr -d ' ')" -eq 22
run_cmd sh -c "cd '$T_TMP/asm-binaries' && if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi"
t_check "SHA256SUMS checks" rc_is 0
t_check "the notices are a release file" test -f "$T_TMP/asm-binaries/THIRD-PARTY-NOTICES.txt"
cp -R "$T_TMP/bins" "$T_TMP/bins-missing"
rm "$T_TMP/bins-missing/$(rel_asset ui "$V" macos-x86_64)"
run_in "$W" scripts/release/assemble.sh binaries "$T_TMP/bins-missing" "$T_TMP/asm-missing"
t_check "assemble.sh: a missing file fails" rc_is 1
t_check "and names it" out_has "missing from the release matrix: $(rel_asset ui "$V" macos-x86_64)"
cp -R "$T_TMP/bins" "$T_TMP/bins-extra"
echo extra >"$T_TMP/bins-extra/lunepack-runtime-$V-windows-aarch64.exe"
run_in "$W" scripts/release/assemble.sh binaries "$T_TMP/bins-extra" "$T_TMP/asm-extra"
t_check "assemble.sh: an extra file fails" rc_is 1
t_check "and names it" out_has "not in the release matrix: lunepack-runtime-$V-windows-aarch64.exe"
cp -R "$T_TMP/bins" "$T_TMP/bins-empty"
: >"$T_TMP/bins-empty/$(rel_asset service "$V" linux-x86_64)"
run_in "$W" scripts/release/assemble.sh binaries "$T_TMP/bins-empty" "$T_TMP/asm-empty"
t_check "assemble.sh: an empty file fails" rc_is 1
make_bins "$T_TMP/bins-other" 9.9.9
run_in "$W" scripts/release/assemble.sh binaries "$T_TMP/bins-other" "$T_TMP/asm-other"
t_check "assemble.sh: files of another version fail" rc_is 1
run_in "$W" scripts/release/assemble.sh tag "$T_TMP/bins" "$T_TMP/asm-tag"
t_check "assemble.sh: mode tag is refused" rc_is 1
run_in "$W" scripts/release/assemble.sh binaries "$T_TMP/bins" "$T_TMP/asm-binaries"
t_check "assemble.sh: an output directory that is not empty is refused" rc_is 1

# --- sign-list.sh ---------------------------------------------------------------------------------
W=$(make_work sign)
make_bins "$T_TMP/sbins"
(cd "$W" && scripts/release/assemble.sh binaries "$T_TMP/sbins" "$T_TMP/s-rel" && scripts/release/assemble.sh rehearsal "$T_TMP/sbins" "$T_TMP/s-reh") >>"$ALL" 2>&1
LIST=$T_TMP/s-rel/prebuilt-$V.json
RLIST=$T_TMP/s-reh/prebuilt-$V.json
n=0
sig_case() { # label, expected rc, expected text, list, mode, then extra env VAR=value...
  local label=$1 rc=$2 text=$3 list=$4 mode=$5
  shift 5
  n=$((n + 1))
  SIG_OUT=$T_TMP/sigs/$n/prebuilt-$V.sig.json
  run_in "$W" env LUNEPACK_PROJECT_KEY="$KEY1" LUNEPACK_CLI="$WRAP" "$@" scripts/release/sign-list.sh "$list" "$SIG_OUT" "$mode"
  t_check "sign-list.sh: $label (exit $rc)" rc_is "$rc"
  t_check "sign-list.sh: $label says $text" out_has "$text"
}
sig_case "a release list in mode binaries" 0 "signed: prebuilt-$V.sig.json" "$LIST" binaries
t_check "the envelope was written" test -s "$SIG_OUT"
run_cmd "$WRAP" prebuilt verify --list "$LIST" --sig "$SIG_OUT"
t_check "and verifies under the trusted key" rc_is 0
GOOD_SIG=$SIG_OUT
sig_case "a rehearsal list in mode rehearsal" 0 "rehearsal true" "$RLIST" rehearsal
# Tracing on: refused before anything else, so nothing of the key can be traced.
n=$((n + 1))
run_in "$W" env LUNEPACK_PROJECT_KEY="$KEY1" LUNEPACK_CLI="$WRAP" bash -x scripts/release/sign-list.sh "$LIST" "$T_TMP/sigs/$n/x.sig.json" binaries
t_check "sign-list.sh: tracing on is refused" rc_is 1
t_check "sign-list.sh: tracing on says so" out_has "shell tracing is on"
t_check "sign-list.sh: tracing on wrote nothing" test ! -e "$T_TMP/sigs/$n"
n=$((n + 1))
run_in "$W" env -u LUNEPACK_PROJECT_KEY LUNEPACK_CLI="$WRAP" scripts/release/sign-list.sh "$LIST" "$T_TMP/sigs/$n/x.sig.json" binaries
t_check "sign-list.sh: no key variable is refused" rc_is 1
t_check "sign-list.sh: no key variable says so" out_has "LUNEPACK_PROJECT_KEY is not set or empty"
sig_case "an empty key variable" 1 "LUNEPACK_PROJECT_KEY is not set or empty" "$LIST" binaries LUNEPACK_PROJECT_KEY=
sig_case "mode dry-run" 1 "mode 'dry-run' is not allowed" "$LIST" dry-run
sig_case "mode tag" 1 "mode 'tag' is not allowed" "$LIST" tag
sig_case "a LUNEPACK_CLI that is not a file" 1 "LUNEPACK_CLI does not name a regular file" "$LIST" binaries LUNEPACK_CLI="$T_TMP/no-such-cli"
cp "$WRAP" "$T_TMP/wrap/noexec"
chmod -x "$T_TMP/wrap/noexec"
sig_case "a LUNEPACK_CLI without the execute bit (made executable)" 0 "signed:" "$LIST" binaries LUNEPACK_CLI="$T_TMP/wrap/noexec"
t_check "the execute bit was restored" test -x "$T_TMP/wrap/noexec"
mkdir -p "$T_TMP/sigs/exists"
echo old >"$T_TMP/sigs/exists/prebuilt-$V.sig.json"
run_in "$W" env LUNEPACK_PROJECT_KEY="$KEY1" LUNEPACK_CLI="$WRAP" scripts/release/sign-list.sh "$LIST" "$T_TMP/sigs/exists/prebuilt-$V.sig.json" binaries
t_check "sign-list.sh: an existing output is refused" rc_is 1
t_check "sign-list.sh: an existing output is left alone" test "$(cat "$T_TMP/sigs/exists/prebuilt-$V.sig.json")" = old
jq '.version = "9.9.9"' "$LIST" >"$T_TMP/other-version.json"
sig_case "a list of another version" 1 "is not the workspace version" "$T_TMP/other-version.json" binaries
sig_case "a rehearsal list in mode binaries" 1 "rehearsal flag is true, mode binaries needs false" "$RLIST" binaries
sig_case "a release list in mode rehearsal" 1 "rehearsal flag is false, mode rehearsal needs true" "$LIST" rehearsal
sig_case "a key that is not the trusted one" 1 "prebuilt sign refused the list" "$LIST" binaries LUNEPACK_PROJECT_KEY="$KEY2"
t_check "sign-list.sh: the wrong key wrote no envelope" test ! -e "$SIG_OUT"
# A member given twice: jq alone reads the last value and calls it valid; the CLI's parser refuses it.
awk 'NR == 2 { print "  \"version\": \"9.9.9\"," } { print }' "$LIST" >"$T_TMP/dup.json"
run_cmd jq -e '.version' "$T_TMP/dup.json"
t_check "jq alone reads the duplicated list as valid" rc_is 0
sig_case "a list with a duplicated member" 1 "does not accept the list" "$T_TMP/dup.json" binaries
t_check "sign-list.sh: the duplicated list wrote no envelope" test ! -e "$SIG_OUT"
(cd "$W" && echo change >>crates/lunepack-cli/src/lib.rs && g commit -q -am "after A") >/dev/null
sig_case "a source_commit that is not HEAD" 1 "source_commit is not HEAD" "$LIST" binaries

# --- check-signing-env.sh -------------------------------------------------------------------------
ENVS=repos_o_r_environments
ENV1=repos_o_r_environments_release-signing
POL=repos_o_r_environments_release-signing_deployment-branch-policies
good_fix() {
  rm -rf "$GH_FIX"
  mkdir -p "$GH_FIX"
  echo '{"total_count":2,"environments":[{"name":"github-pages"},{"name":"release-signing"}]}' >"$GH_FIX/$ENVS.json"
  echo '{"name":"release-signing","can_admins_bypass":false,"protection_rules":[{"type":"wait_timer","wait_timer":0},{"type":"required_reviewers","prevent_self_review":false,"reviewers":[{"type":"User","reviewer":{"login":"maintainer"}}]}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}' >"$GH_FIX/$ENV1.json"
  echo '{"total_count":1,"branch_policies":[{"name":"main","type":"branch"}]}' >"$GH_FIX/$POL.json"
}
env_edit() { # file key, jq filter
  jq -c "$2" "$GH_FIX/$1.json" >"$GH_FIX/$1.tmp"
  mv "$GH_FIX/$1.tmp" "$GH_FIX/$1.json"
}
env_case() { # label, mode, expected rc, expected text
  : >"$GH_LOG"
  run_in "$W" env GITHUB_REPOSITORY=o/r scripts/release/check-signing-env.sh "$2"
  t_check "check-signing-env.sh: $1 ($2, exit $3)" rc_is "$3"
  t_check "check-signing-env.sh: $1 ($2) says $4" out_has "$4"
}
good_fix
env_case "a configured environment" binaries 0 "release-signing: ok"
t_check "it called the three endpoints in order" test "$(cat "$GH_LOG")" = "api repos/o/r/environments
api repos/o/r/environments/release-signing
api repos/o/r/environments/release-signing/deployment-branch-policies"
env_case "a configured environment" dry-run 0 "release-signing: ok"
good_fix
echo 403 >"$GH_FIX/$ENVS.status"
env_case "a 403 from the list" dry-run 1 "failed (the token cannot read the environments)"
env_case "a 403 from the list" binaries 1 "failed (the token cannot read the environments)"
good_fix
env_edit "$ENVS" '.total_count = 1 | .environments = [{"name":"github-pages"}]'
env_case "no release-signing" binaries 1 "release-signing: not configured (total_count 1)"
env_case "no release-signing" dry-run 0 "release-signing: not configured (total_count 1)"
t_check "dry-run without the environment called the list only" test "$(cat "$GH_LOG")" = "api repos/o/r/environments"
good_fix
env_edit "$ENV1" '.protection_rules = [{"type":"wait_timer","wait_timer":5}]'
env_case "no reviewer rule" binaries 1 "no required_reviewers rule"
env_case "no reviewer rule" dry-run 0 "not ready"
good_fix
env_edit "$ENV1" '.protection_rules = [{"type":"required_reviewers","reviewers":[]}]'
env_case "a reviewer rule with no reviewer" rehearsal 1 "no required_reviewers rule"
good_fix
env_edit "$ENV1" '.can_admins_bypass = true'
env_case "can_admins_bypass true" binaries 1 "can_admins_bypass is not false"
good_fix
env_edit "$ENV1" 'del(.can_admins_bypass)'
env_case "can_admins_bypass absent" binaries 1 "can_admins_bypass is not false"
good_fix
env_edit "$ENV1" '.can_admins_bypass = null'
env_case "can_admins_bypass null" tag 1 "can_admins_bypass is not false"
good_fix
env_edit "$ENV1" '.deployment_branch_policy = null'
env_case "deployment_branch_policy null" binaries 1 "deployment_branch_policy is not custom branch policies only"
t_check "a null branch policy never called the policies endpoint" test "$(grep -c 'deployment-branch-policies' "$GH_LOG" || true)" -eq 0
good_fix
env_edit "$ENV1" '.deployment_branch_policy.protected_branches = true'
env_case "protected_branches true" binaries 1 "deployment_branch_policy is not custom branch policies only"
good_fix
env_edit "$ENV1" '.deployment_branch_policy.custom_branch_policies = false'
env_case "custom_branch_policies false" binaries 1 "deployment_branch_policy is not custom branch policies only"
t_check "custom_branch_policies false never called the policies endpoint" test "$(grep -c 'deployment-branch-policies' "$GH_LOG" || true)" -eq 0
good_fix
echo 404 >"$GH_FIX/$POL.status"
env_case "a 404 from the policies endpoint" binaries 1 "GET deployment-branch-policies failed"
good_fix
env_edit "$POL" '.total_count = 2 | .branch_policies += [{"name":"release-rehearsal","type":"branch"}]'
env_case "a second branch policy" binaries 1 "the branch policies are not exactly one: the branch main"
good_fix
env_edit "$POL" '.branch_policies = [{"name":"main","type":"tag"}]'
env_case "a tag policy named main" binaries 1 "the branch policies are not exactly one: the branch main"
good_fix
echo 500 >"$GH_FIX/$ENV1.status"
env_case "an error from the environment endpoint" binaries 1 "GET repos/o/r/environments/release-signing failed"
good_fix
echo '{"total_count":"2","environments":{}}' >"$GH_FIX/$ENVS.json"
env_case "a list of the wrong shape" dry-run 1 "no numeric total_count"
run_in "$W" env -u GITHUB_REPOSITORY scripts/release/check-signing-env.sh binaries
t_check "check-signing-env.sh: no GITHUB_REPOSITORY is refused" rc_is 1

# --- the release, end to end: assemble, sign, attach's verification, pin, commit, verify-pins --------
export WRAP_PUB=$PUB1
W=$(make_work rel)
A=$(g -C "$W" rev-parse HEAD)
phase1 "$W" binaries "v$V" || t_fail "phase 1 (release) failed"
t_check "phase 1 put the list and the envelope into the draft" test -f "$GH_RELEASES/v$V/prebuilt-$V.sig.json"
: >"$GH_LOG"
run_in "$W" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh
t_check "pin.sh at A passes" rc_is 0
t_check "pin.sh prints the order: land on main, then tag" out_has "only then tag the commit that is on main"
t_check "pin.sh downloaded only the two files" grep -Fxq "release download v$V --pattern prebuilt-$V.json --pattern prebuilt-$V.sig.json --dir" <(sed 's| --dir .*| --dir|' "$GH_LOG")
t_check "pin.sh copied the list byte for byte" cmp -s "$W/crates/lunepack-cli/prebuilt.json" "$GH_RELEASES/v$V/prebuilt-$V.json"
t_check "pin.sh copied the envelope byte for byte" cmp -s "$W/crates/lunepack-cli/prebuilt.sig.json" "$GH_RELEASES/v$V/prebuilt-$V.sig.json"
t_check "pin.sh committed nothing" test "$(g -C "$W" rev-parse HEAD)" = "$A"
(cd "$W" && g commit -q -am "pin $V" && g push -q origin main) >/dev/null
B=$(g -C "$W" rev-parse HEAD)
run_in "$W" env LUNEPACK_CLI="$WRAP" GITHUB_REF="refs/tags/v$V" scripts/release/verify-pins.sh "$GH_RELEASES/v$V" tag
t_check "verify-pins.sh at B passes (tag)" rc_is 0
t_check "verify-pins.sh names A" out_has "source commit $A"

# verify-pins.sh failures, each on a copy of the passing state.
vp_case() { # label, work, assets, mode, expected text, then VAR=value...
  local label=$1 w=$2 assets=$3 mode=$4 text=$5
  shift 5
  run_in "$w" env LUNEPACK_CLI="$WRAP" "$@" scripts/release/verify-pins.sh "$assets" "$mode"
  t_check "verify-pins.sh: $label fails" rc_is 1
  t_check "verify-pins.sh: $label says $text" out_has "$text"
}
copy_draft() { # name -> a copy of the release draft
  rm -rf "${T_TMP:?}/$1"
  cp -R "$GH_RELEASES/v$V" "$T_TMP/$1"
  printf '%s\n' "$T_TMP/$1"
}
D=$(copy_draft d-env)
printf '\n' >>"$D/prebuilt-$V.sig.json"
vp_case "a committed envelope that is not the draft's" "$W" "$D" tag "the committed envelope is not the draft's"
D=$(copy_draft d-list)
printf ' ' >>"$D/prebuilt-$V.json"
vp_case "a committed table that is not the draft's" "$W" "$D" tag "the committed table is not the draft's"
D=$(copy_draft d-file)
printf 'x' >>"$D/$(rel_asset runtime "$V" linux-x86_64)"
vp_case "a draft file that differs from its row" "$W" "$D" tag "prebuilt verify failed"
D=$(copy_draft d-missing)
rm "$D/$(rel_asset stub "$V" windows-x86_64)"
vp_case "a draft file missing (--all)" "$W" "$D" tag "prebuilt verify failed"
vp_case "a release list in rehearsal-finalize" "$W" "$GH_RELEASES/v$V" rehearsal-finalize "rehearsal flag is false, mode rehearsal-finalize needs true" GITHUB_REF=refs/heads/release-rehearsal
# A list edited after signing: the committed table and the draft's list both changed, so cmp passes
# and the signature check fails.
W2=$(make_work rel-edit)
phase1 "$W2" binaries "v$V" || t_fail "phase 1 (edited list) failed"
(cd "$W2" && LUNEPACK_CLI="$WRAP" scripts/release/pin.sh) >>"$ALL" 2>&1 || t_fail "pin.sh (edited list) failed"
sed 's/"rehearsal": false/"rehearsal": false /' "$W2/crates/lunepack-cli/prebuilt.json" >"$T_TMP/edited.json"
cp "$T_TMP/edited.json" "$W2/crates/lunepack-cli/prebuilt.json"
(cd "$W2" && g commit -q -am "pin, edited" && g push -q origin main) >/dev/null
D=$(copy_draft d-edited)
cp "$T_TMP/edited.json" "$D/prebuilt-$V.json"
vp_case "a list edited after signing" "$W2" "$D" tag "prebuilt verify failed"
# A third file in A..B.
W3=$(make_work rel-third)
phase1 "$W3" binaries "v$V" || t_fail "phase 1 (third file) failed"
(cd "$W3" && LUNEPACK_CLI="$WRAP" scripts/release/pin.sh) >>"$ALL" 2>&1 || t_fail "pin.sh (third file) failed"
(cd "$W3" && echo "// another key set" >>crates/lunepack-cli/src/project_key.rs && g commit -q -am "pin and a key" && g push -q origin main) >/dev/null
vp_case "a third file in A..B (project_key.rs)" "$W3" "$GH_RELEASES/v$V" tag "change other files than the two pin files"
# A tagged commit that is not on main.
W4=$(make_work rel-offmain)
phase1 "$W4" binaries "v$V" || t_fail "phase 1 (off main) failed"
(cd "$W4" && LUNEPACK_CLI="$WRAP" scripts/release/pin.sh) >>"$ALL" 2>&1 || t_fail "pin.sh (off main) failed"
(cd "$W4" && g commit -q -am "pin, never pushed") >/dev/null
vp_case "a tagged commit not on main" "$W4" "$GH_RELEASES/v$V" tag "the tagged commit is not on origin/main"

# --- pin.sh failures ----------------------------------------------------------------------------
W5=$(make_work pin)
phase1 "$W5" binaries "v$V" || t_fail "phase 1 (pin cases) failed"
echo dirt >"$W5/untracked.txt"
run_in "$W5" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh
t_check "pin.sh: a dirty tree (an untracked file) is refused" rc_is 1
t_check "pin.sh: a dirty tree says so" out_has "the work tree is not clean"
rm "$W5/untracked.txt"
run_in "$W5" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh --rehearsal
t_check "pin.sh --rehearsal without a rehearsal draft is refused" rc_is 1
t_check "pin.sh --rehearsal says which draft" out_has "v$V-rehearsal"
run_in "$W5" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh --other
t_check "pin.sh: an unknown argument is a usage error" rc_is 2
(cd "$W5" && echo more >>crates/lunepack-cli/src/lib.rs && g commit -q -am "not A") >/dev/null
run_in "$W5" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh
t_check "pin.sh: HEAD not A is refused" rc_is 1
t_check "pin.sh: HEAD not A says so" out_has "is not HEAD"
t_check "pin.sh: HEAD not A copied nothing" test ! -s "$W5/crates/lunepack-cli/prebuilt.json"
g -C "$W5" reset -q --hard HEAD~1
# HEAD (A) not on origin/main: A committed and never pushed.
W6=$(make_work pin-unpushed)
(cd "$W6" && echo local >>crates/lunepack-cli/src/lib.rs && g commit -q -am "A, never pushed") >/dev/null
phase1 "$W6" binaries "v$V" || t_fail "phase 1 (unpushed) failed"
run_in "$W6" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh
t_check "pin.sh: HEAD not on origin/main is refused" rc_is 1
t_check "pin.sh: HEAD not on origin/main says so" out_has "HEAD is not on origin/main"
W7=$(make_work pin-noorigin)
g -C "$W7" remote remove origin
phase1 "$W7" binaries "v$V" || t_fail "phase 1 (no origin) failed"
run_in "$W7" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh
t_check "pin.sh: a missing origin/main is a failure" rc_is 1
t_check "pin.sh: a missing origin/main says so" out_has "cannot fetch main from origin"
# A rehearsal list in the release draft: the flag does not match.
W8=$(make_work pin-flag)
phase1 "$W8" rehearsal "v$V-rehearsal" || t_fail "phase 1 (flag) failed"
rm -rf "$GH_RELEASES/v$V"
cp -R "$GH_RELEASES/v$V-rehearsal" "$GH_RELEASES/v$V"
run_in "$W8" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh
t_check "pin.sh: a rehearsal list in the release draft is refused" rc_is 1
t_check "pin.sh: the flag mismatch says so" out_has "rehearsal flag is true, this run expects false"
# A list edited after signing, in the draft.
W9=$(make_work pin-edited)
phase1 "$W9" binaries "v$V" || t_fail "phase 1 (pin edited) failed"
sed 's/"rehearsal": false/"rehearsal": false /' "$GH_RELEASES/v$V/prebuilt-$V.json" >"$T_TMP/pin-edited.json"
cp "$T_TMP/pin-edited.json" "$GH_RELEASES/v$V/prebuilt-$V.json"
run_in "$W9" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh
t_check "pin.sh: a list edited after signing is refused" rc_is 1
t_check "pin.sh: the edited list fails the signature check" out_has "does not verify under this CLI's built-in key"
t_check "pin.sh: the edited list copied nothing" test ! -s "$W9/crates/lunepack-cli/prebuilt.json"
# Signed by a key that is not this CLI's.
W10=$(make_work pin-key)
phase1 "$W10" binaries "v$V" || t_fail "phase 1 (pin key) failed"
run_in "$W10" env LUNEPACK_CLI="$WRAP" WRAP_PUB="$PUB2" scripts/release/pin.sh
t_check "pin.sh: an envelope of another key is refused" rc_is 1

# --- the rehearsal, end to end ----------------------------------------------------------------------
W=$(make_work reh)
A=$(g -C "$W" rev-parse HEAD)
phase1 "$W" rehearsal "v$V-rehearsal" || t_fail "phase 1 (rehearsal) failed"
run_in "$W" env LUNEPACK_CLI="$WRAP" scripts/release/pin.sh --rehearsal
t_check "pin.sh --rehearsal at A passes" rc_is 0
t_check "pin.sh --rehearsal names the branch release-rehearsal" out_has "release-rehearsal"
(cd "$W" && g switch -q -c release-rehearsal && g commit -q -am "pin rehearsal" && g push -q origin release-rehearsal) >/dev/null
run_in "$W" env LUNEPACK_CLI="$WRAP" GITHUB_REF=refs/heads/release-rehearsal scripts/release/verify-pins.sh "$GH_RELEASES/v$V-rehearsal" rehearsal-finalize
t_check "verify-pins.sh passes (rehearsal-finalize)" rc_is 0
t_check "verify-pins.sh reports the state rehearsal" out_has "state rehearsal"
vp_case "a rehearsal list in tag mode" "$W" "$GH_RELEASES/v$V-rehearsal" tag "prebuilt verify failed"
t_check "verify-pins.sh: the CLI refused it as a rehearsal list" out_has "rehearsal list"
vp_case "rehearsal-finalize on another ref" "$W" "$GH_RELEASES/v$V-rehearsal" rehearsal-finalize "runs on refs/heads/release-rehearsal only" GITHUB_REF=refs/heads/main

# --- what nothing may do ---------------------------------------------------------------------------
t_check "no output of any case holds the base64 body of a throwaway key (1)" test "$(grep -cF -- "$BODY1" "$ALL" || true)" -eq 0
t_check "no output of any case holds the base64 body of a throwaway key (2)" test "$(grep -cF -- "$BODY2" "$ALL" || true)" -eq 0
t_check "the body check is armed (the body is long)" test "${#BODY1}" -gt 40
t_check "the gh stand-in recorded calls (the log is armed)" test -s "$GH_ALL_LOG"
t_check "the gh stand-in recorded no gh attestation call" test "$(grep -c '^attestation' "$GH_ALL_LOG" || true)" -eq 0
t_check "the gh stand-in recorded no gh secret call" test "$(grep -c '^secret' "$GH_ALL_LOG" || true)" -eq 0
if command -v gitleaks >/dev/null 2>&1; then
  mkdir -p "$T_TMP/leaks"
  cp "$GOOD_SIG" "$T_TMP/leaks/"
  cp "$LIST" "$T_TMP/leaks/"
  run_cmd gitleaks dir --no-banner --redact "$T_TMP/leaks"
  t_check "gitleaks dir finds nothing in a fixture envelope and its list" rc_is 0
  if [ "$RC" -ne 0 ]; then sed 's/^/    /' "$OUT" >&2; fi
else
  t_fail "gitleaks is not on PATH (scripts/tests/run.sh needs it)"
fi

t_finish
