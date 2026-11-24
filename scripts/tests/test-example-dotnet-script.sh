#!/usr/bin/env bash
# Tests for scripts/build-example-dotnet.sh. Nothing here runs the real dotnet: a valid target is given
# with --print-command, or the build runs in a scratch copy of the script with a stub dotnet on a PATH
# that holds nothing else but ls, find, wc, tr, cat, mkdir and cp.
# shellcheck disable=SC2016,SC2034 # SC2016: the stub body is a script; SC2034: RC is read by lib.sh
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
SCRIPT=$here/../build-example-dotnet.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

run_cmd bash "$SCRIPT"
t_check "no argument is a usage error" rc_is 2
t_check "usage is printed" out_has "usage:"

run_cmd bash "$SCRIPT" linux-x86_64
t_check "no out-dir is a usage error" rc_is 2

run_cmd bash "$SCRIPT" linux-x86_64 "$T_TMP/o" extra
t_check "a stray argument is a usage error" rc_is 2

run_cmd bash "$SCRIPT" linux-x86_64 ""
t_check "an empty out-dir is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --print-command --print-command linux-x86_64 "$T_TMP/o"
t_check "--print-command twice is a usage error" rc_is 2

run_cmd bash "$SCRIPT" windows-aarch64 "$T_TMP/o"
t_check "a target outside the table is refused" rc_is 2
t_check "the refusal says so" out_has "unknown target"

run_cmd bash "$SCRIPT" x86_64-unknown-linux-gnu "$T_TMP/o"
t_check "a triple is not a target id" rc_is 2

run_cmd bash "$SCRIPT" macos-universal "$T_TMP/o"
t_check "macos-universal is refused" rc_is 2
t_check "the refusal says it is built per architecture" out_has "built per architecture"
t_check "and names the thin targets" out_has "macos-aarch64 or macos-x86_64"

run_cmd bash "$SCRIPT" --macos-bundle "$T_TMP/b" macos-aarch64
t_check "--macos-bundle with one positional is a usage error" rc_is 2

run_cmd bash "$SCRIPT" linux-x86_64 "$T_TMP/o" --macos-bundle
t_check "--macos-bundle without a value is a usage error" rc_is 2

run_cmd bash "$SCRIPT" macos-aarch64 "$T_TMP/o" --macos-bundle "$T_TMP/b" --macos-bundle "$T_TMP/c"
t_check "--macos-bundle twice is a usage error" rc_is 2

run_cmd bash "$SCRIPT" linux-x86_64 "$T_TMP/o" --macos-bundle "$T_TMP/b"
t_check "--macos-bundle on a Linux target is refused" rc_is 2
t_check "the refusal names macos-*" out_has "needs a macos-* target"

run_cmd bash "$SCRIPT" windows-x86_64 "$T_TMP/o" --macos-bundle "$T_TMP/b"
t_check "--macos-bundle on a Windows target is refused" rc_is 2

run_cmd bash "$SCRIPT" --help
t_check "--help exits 0" rc_is 0
t_check "--help prints usage" out_has "usage:"

# --- --print-command: the table of runtime identifiers, and nothing runs --------------------
BASH_BIN=$(command -v bash)
repo=$T_TMP/repo
stubs=$T_TMP/stubs
mkdir -p "$repo/scripts" "$repo/examples/dotnet" "$stubs"
cp "$SCRIPT" "$repo/scripts/build-example-dotnet.sh"
for tool in ls find wc tr cat mkdir cp; do
  ln -s "$(command -v "$tool")" "$stubs/$tool"
done
printf '#!/bin/sh\n%s\n' 'echo "$@" >>"$STUB_LOG"
echo "pwd=$PWD" >>"$STUB_LOG"
out=
host=
while [ "$#" -gt 0 ]; do
  case $1 in
    -o) out=$2 ;;
    -p:MacBundleHost=*) host=${1#-p:MacBundleHost=} ;;
  esac
  shift
done
mkdir -p "$out/sub"
if [ "${STUB_MODE:-}" != nohost ]; then echo exe >"$out/${STUB_HOST:-Example}"; fi
echo dll >"$out/Example.dll"
echo lib >"$out/sub/lib.dylib"
if [ "${STUB_MODE:-}" = pdb ]; then echo debug >"$out/Example.pdb"; fi
if [ -n "$host" ]; then echo bundlehost >"$host"; fi' >"$stubs/dotnet"
chmod +x "$stubs/dotnet"

# A run of the scratch copy, from the scratch directory, with the stub PATH.
run_script() {
  RC=0
  (cd "$T_TMP" && env STUB_LOG="$T_TMP/dotnet.args" STUB_MODE="${STUB_MODE:-}" STUB_HOST="${STUB_HOST:-}" PATH="$stubs" "$BASH_BIN" "$repo/scripts/build-example-dotnet.sh" "$@") >"$OUT" 2>&1 || RC=$?
}

check_rid() { # target, rid
  rm -f "$T_TMP/dotnet.args"
  run_script --print-command "$1" "$T_TMP/pc-out"
  t_check "$1: --print-command exits 0" rc_is 0
  t_check "$1: publishes for $2" out_has " -r $2 "
  t_check "$1: self-contained" out_has " --self-contained "
  t_check "$1: Release" out_has " -c Release "
  t_check "$1: into the out-dir" out_has " -o $T_TMP/pc-out "
  t_check "$1: no bundle property" out_lacks "MacBundleHost"
  t_check "$1: dotnet did not run" test ! -e "$T_TMP/dotnet.args"
}
# The stub dotnet is on PATH from here on: --print-command must still not run it.
check_rid linux-x86_64 linux-x64
check_rid linux-aarch64 linux-arm64
check_rid windows-x86_64 win-x64
check_rid macos-aarch64 osx-arm64
check_rid macos-x86_64 osx-x64

run_script --print-command macos-aarch64 "$T_TMP/pc-out" --macos-bundle "$T_TMP/pc-bundle"
t_check "a bundle print exits 0" rc_is 0
t_check "it passes the host's place" out_has "-p:MacBundleHost=$T_TMP/pc-bundle/Contents/MacOS/Example"
t_check "dotnet did not run for it either" test ! -e "$T_TMP/dotnet.args"

run_script --print-command linux-x86_64 relative-out
t_check "a relative out-dir is made absolute" out_has " -o $(cd "$T_TMP" && pwd)/relative-out "

run_script --print-command linux-x86_64 "$T_TMP/pc-out" --macos-bundle
t_check "a print with a bundle option and no value is a usage error" rc_is 2

# --- directories: absent or empty out-dir, absent bundle ----------------------------------
mkdir -p "$T_TMP/full" "$T_TMP/empty"
echo x >"$T_TMP/full/file"
run_script --print-command linux-x86_64 "$T_TMP/full"
t_check "a non-empty out-dir is refused" rc_is 1
t_check "the refusal says so" out_has "not empty"

run_script --print-command linux-x86_64 "$T_TMP/empty"
t_check "an empty out-dir is accepted" rc_is 0

echo x >"$T_TMP/afile"
run_script --print-command linux-x86_64 "$T_TMP/afile"
t_check "a file as out-dir is refused" rc_is 1

mkdir -p "$T_TMP/existing-bundle"
run_script --print-command macos-aarch64 "$T_TMP/pc-out" --macos-bundle "$T_TMP/existing-bundle"
t_check "an existing bundle path is refused" rc_is 1
t_check "the refusal says so" out_has "exists"

run_script --print-command macos-aarch64 "$T_TMP/pc-out" --macos-bundle "$T_TMP/pc-out"
t_check "the bundle cannot be the out-dir" rc_is 1

# --- the build, against the stub ------------------------------------------------------------
run_script linux-aarch64 "$T_TMP/b-linux"
t_check "a Linux build succeeds" rc_is 0
t_check "the stub saw the publish" grep -q -- "-r linux-arm64 --self-contained" "$T_TMP/dotnet.args"
t_check "it ran from the example's directory (global.json)" grep -q "^pwd=.*/examples/dotnet$" "$T_TMP/dotnet.args"
t_check "the output holds the host" test -f "$T_TMP/b-linux/Example"
t_check "the summary counts the files" out_has "3 files in $T_TMP/b-linux"

rm -f "$T_TMP/dotnet.args"
STUB_HOST=Example.exe run_script windows-x86_64 "$T_TMP/b-win"
t_check "a Windows build succeeds with an .exe host" rc_is 0
t_check "the Windows host is Example.exe" test -f "$T_TMP/b-win/Example.exe"

STUB_MODE=nohost run_script linux-x86_64 "$T_TMP/b-nohost"
t_check "a publish without the host fails" rc_is 1
t_check "and says which file" out_has "did not write $T_TMP/b-nohost/Example"

STUB_MODE=pdb run_script linux-x86_64 "$T_TMP/b-pdb"
t_check "a publish with a .pdb fails" rc_is 1
t_check "and says so" out_has ".pdb"

run_script linux-x86_64 "$T_TMP/b-linux"
t_check "a second run into the same out-dir is refused" rc_is 1

# The bundle: the host alone in Contents/MacOS, the rest under Contents/Resources/app, inside the out-dir.
bundle=$T_TMP/b-mac/Example.app
run_script macos-aarch64 "$T_TMP/b-mac" --macos-bundle "$bundle"
t_check "a bundle build succeeds" rc_is 0
t_check "the publish got the host's place" grep -q -- "-p:MacBundleHost=$bundle/Contents/MacOS/Example" "$T_TMP/dotnet.args"
t_check "the host is in Contents/MacOS" test -f "$bundle/Contents/MacOS/Example"
t_check "and alone there" test "$(ls "$bundle/Contents/MacOS")" = Example
t_check "the managed file is under Contents/Resources/app" test -f "$bundle/Contents/Resources/app/Example.dll"
t_check "a nested file keeps its place" test -f "$bundle/Contents/Resources/app/sub/lib.dylib"
t_check "the flat host is not copied into the bundle" test ! -e "$bundle/Contents/Resources/app/Example"
t_check "the bundle is not copied into itself" test ! -e "$bundle/Contents/Resources/app/Example.app"
t_check "the Info.plist names the executable" grep -q "<key>CFBundleExecutable</key><string>Example</string>" "$bundle/Contents/Info.plist"
t_check "the flat output stays" test -f "$T_TMP/b-mac/Example.dll"
t_check "the summary names the bundle" out_has "bundle $bundle"

# A bundle outside the out-dir.
run_script macos-x86_64 "$T_TMP/b-mac2" --macos-bundle "$T_TMP/elsewhere/Example.app"
t_check "a bundle outside the out-dir builds" rc_is 0
t_check "with the host alone in Contents/MacOS" test "$(ls "$T_TMP/elsewhere/Example.app/Contents/MacOS")" = Example

# No dotnet on PATH.
rm -f "$stubs/dotnet"
run_script linux-x86_64 "$T_TMP/b-nodotnet"
t_check "no dotnet is an error" rc_is 1
t_check "which says dotnet is not on PATH" out_has "dotnet is not on PATH"

t_finish
