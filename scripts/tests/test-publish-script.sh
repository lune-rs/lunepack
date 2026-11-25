#!/usr/bin/env bash
# Tests for scripts/publish-dry-run.sh. Nothing here runs the real cargo or reaches a registry: the
# script runs in a scratch copy with a stub cargo on a PATH that holds only the tools it needs.
# shellcheck disable=SC2016,SC2034 # SC2016: the stub body is a script; SC2034: RC is read by lib.sh
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
SCRIPT=$here/../publish-dry-run.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

BASH_BIN=$(command -v bash)
repo=$T_TMP/repo
stubs=$T_TMP/stubs
mkdir -p "$repo/scripts" "$stubs"
cp "$SCRIPT" "$repo/scripts/publish-dry-run.sh"
for tool in mktemp tee awk sort rm sed cat; do
  ln -s "$(command -v "$tool")" "$stubs/$tool"
done

# The ten names, in the order cargo packages them (the order is not the script's concern).
NAMES="lunepack-core lunepack-codec-lzma lunepack-crypto lunepack-fs lunepack-http lunepack-os-linux lunepack-os-macos lunepack-os-windows lunepack lunepack-cli"

# A stub cargo: records its arguments, then prints what STUB_MODE says a cargo run prints.
cat >"$stubs/cargo" <<'STUB'
#!/bin/sh
echo "$*" >>"$STUB_LOG"
echo "pwd=$(pwd -P)" >>"$STUB_LOG"
upload() { # name
  echo "   Uploading $1 v0.1.0 (/some/where/$1)"
  echo "warning: aborting upload due to dry run"
}
echo "    Updating crates.io index"
case ${STUB_MODE:-ok} in
  fail)
    echo "error: 3 files in the working directory contain changes that were not yet committed into git"
    exit 101
    ;;
esac
n=0
for name in $STUB_NAMES; do
  n=$((n + 1))
  case ${STUB_MODE:-ok} in
    noabort)
      if [ "$name" = "${STUB_BAD:-}" ]; then
        echo "   Uploading $name v0.1.0 (/some/where/$name)"
        echo "error: something else"
        continue
      fi
      ;;
    lastnoabort)
      if [ "$n" -eq 10 ]; then
        echo "   Uploading $name v0.1.0 (/some/where/$name)"
        continue
      fi
      ;;
  esac
  upload "$name"
done
exit 0
STUB
chmod +x "$stubs/cargo"

run_script() {
  RC=0
  (cd "$T_TMP" && env -i STUB_LOG="$T_TMP/cargo.args" STUB_MODE="${STUB_MODE:-ok}" STUB_NAMES="${STUB_NAMES-$NAMES}" STUB_BAD="${STUB_BAD:-}" \
    PATH="$stubs" TMPDIR="$T_TMP" "$@" "$BASH_BIN" "$repo/scripts/publish-dry-run.sh" ${ARGS:+$ARGS}) >"$OUT" 2>&1 || RC=$?
}

# --- the invocation --------------------------------------------------------------------------
run_script
t_check "the ten crates reaching the abort pass" rc_is 0
t_check "it says ok" out_has "ok (10 crates reached the dry-run abort)"
t_check "cargo got exactly publish --workspace --dry-run --locked" grep -qx "publish --workspace --dry-run --locked" "$T_TMP/cargo.args"
t_check "cargo ran once" test "$(grep -c -v '^pwd=' "$T_TMP/cargo.args")" -eq 1
t_check "from the repository root" grep -q "^pwd=$(cd "$repo" && pwd -P)\$" "$T_TMP/cargo.args"
t_check "cargo's output is shown" out_has "Updating crates.io index"

ARGS=--publish run_script
t_check "an argument is a usage error" rc_is 2
t_check "it says --dry-run is fixed" out_has "--dry-run is fixed"
ARGS=--help run_script
t_check "--help exits 0" rc_is 0
t_check "--help prints usage" out_has "usage:"
unset ARGS

# --- tokens in the environment ---------------------------------------------------------------
rm -f "$T_TMP/cargo.args"
run_script CARGO_REGISTRY_TOKEN=secret-value-1
t_check "CARGO_REGISTRY_TOKEN stops the run" rc_is 1
t_check "it names the variable" out_has "CARGO_REGISTRY_TOKEN"
t_check "it never prints the value" out_lacks "secret-value-1"
t_check "cargo did not run" test ! -e "$T_TMP/cargo.args"

run_script CARGO_REGISTRIES_PRIVATE_TOKEN=secret-value-2
t_check "a per-registry token stops the run" rc_is 1
t_check "it names that variable" out_has "CARGO_REGISTRIES_PRIVATE_TOKEN"
t_check "and never prints its value" out_lacks "secret-value-2"
t_check "cargo did not run for it either" test ! -e "$T_TMP/cargo.args"

run_script CARGO_REGISTRIES_PRIVATE_INDEX=https://example.invalid/index
t_check "another per-registry variable is not a token" rc_is 0

# --- what must reach the upload --------------------------------------------------------------
STUB_MODE=fail run_script
t_check "a failing cargo fails the script" rc_is 1
t_check "and says its exit status" out_has "exit 101"

STUB_NAMES="${NAMES% lunepack-cli}" run_script
t_check "nine crates fail" rc_is 1
t_check "the missing one is visible in the list" out_has "expected:"

STUB_NAMES="$NAMES lunepack-runtime" run_script
t_check "an eleventh crate fails" rc_is 1
t_check "and is named" out_has "lunepack-runtime"

STUB_NAMES="${NAMES% lunepack-cli} lunepack-service" run_script
t_check "a wrong name in place of one fails" rc_is 1

STUB_NAMES="$NAMES lunepack-core" run_script
t_check "a crate twice fails" rc_is 1

STUB_NAMES="" run_script
t_check "no crate at all fails" rc_is 1

STUB_MODE=noabort STUB_BAD=lunepack-fs run_script
t_check "an upload line without the dry-run abort fails" rc_is 1
t_check "it names the crate" out_has "no dry-run abort followed the upload of: lunepack-fs"

STUB_MODE=lastnoabort run_script
t_check "an upload line at the very end without the abort fails" rc_is 1

t_finish
