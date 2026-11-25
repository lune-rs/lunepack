#!/usr/bin/env bash
# Tests for scripts/build-runtime.sh. Nothing here runs the real cargo: a valid target is given with
# --print-command, or the build runs in a scratch copy of the script with stub cargo, readelf,
# lipo, otool, uname and musl-gcc on a PATH that holds nothing else but cp, wc, mkdir, sort, tr
# and awk.
# shellcheck disable=SC2016,SC2034 # SC2016: stub bodies are scripts; SC2034: RC is read by lib.sh
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
t_check "a Windows target is refused" rc_is 2
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

run_cmd bash "$SCRIPT" --print-command macos-aarch64
t_check "macos-aarch64 prints its command" rc_is 0
t_check "with the Apple triple" out_has "--target aarch64-apple-darwin"
t_check "with the deployment target" out_has "MACOSX_DEPLOYMENT_TARGET=10.15 cargo build --locked --release -p lunepack-runtime"

run_cmd bash "$SCRIPT" --print-command macos-x86_64
t_check "macos-x86_64 prints its command" rc_is 0
t_check "with its Apple triple" out_has "--target x86_64-apple-darwin"

run_cmd bash "$SCRIPT" --print-command macos-universal
t_check "macos-universal prints both builds" rc_is 0
t_check "the aarch64 build" out_has "--target aarch64-apple-darwin"
t_check "the x86_64 build" out_has "--target x86_64-apple-darwin"
t_check "and the lipo join" out_has "lipo -create -output target/universal-apple-darwin/release/lunepack-runtime"

run_cmd bash "$SCRIPT" --help
t_check "--help exits 0" rc_is 0
t_check "the usage lists the macOS targets" out_has "macos-universal"
t_check "the usage says the deployment target binds x86_64 only" out_has "binds the x86_64 slice only"
t_check "and that aarch64 keeps its own minimum" out_has "aarch64 slice keeps Rust's 11.0 minimum"

# --- the build path, against stubs --------------------------------------------------------
BASH_BIN=$(command -v bash)
repo=$T_TMP/repo
stubs=$T_TMP/stubs
mkdir -p "$repo/scripts" "$stubs"
cp "$SCRIPT" "$repo/scripts/build-runtime.sh"
for tool in cp wc mkdir sort tr awk; do
  ln -s "$(command -v "$tool")" "$stubs/$tool"
done
stub() { # name, body (a /bin/sh script)
  printf '#!/bin/sh\n%s\n' "$2" >"$stubs/$1"
  chmod +x "$stubs/$1"
}
stub uname 'case "$1" in
  -s) echo "${STUB_OS:-Linux}" ;;
  *) echo "${STUB_UNAME:-x86_64}" ;;
esac'
stub musl-gcc 'exit 0'
stub cargo 'echo "MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-unset} $@" >>"$STUB_LOG"
p=lunepack-runtime
while [ "$#" -gt 0 ]; do
  if [ "$1" = --target ]; then t=$2; fi
  if [ "$1" = -p ]; then p=$2; fi
  shift
done
d=${CARGO_TARGET_DIR:-target}/$t/release
mkdir -p "$d"
printf "0123456789" >"$d/$p"'
stub readelf 'case "$1" in
  -hW) echo "  Machine:                           ${STUB_MACHINE:-Advanced Micro Devices X86-64}" ;;
  -lW)
    echo "Program Headers:"
    echo "  LOAD           0x000000 0x0000 0x0000 0x000100 0x000100 R E 0x1000"
    if [ -n "${STUB_INTERP:-}" ]; then echo "  INTERP         0x000200 0x0200 0x0200 0x00001c 0x00001c R   0x1"; fi
    ;;
  -dW)
    echo "Dynamic section at offset 0x100 contains 1 entries:"
    if [ -n "${STUB_NEEDED:-}" ]; then echo " 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]"; fi
    ;;
esac
[ -z "${STUB_NOT_ELF:-}" ]'

# sbuild [VAR=value]... -- args: runs the scratch copy with only the stubs on PATH.
sbuild() {
  rm -f "$T_TMP/cargo.args"
  local envs=()
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
    envs+=("$1")
    shift
  done
  shift
  RC=0
  (cd "$T_TMP" && env STUB_LOG="$T_TMP/cargo.args" PATH="$stubs" ${envs[@]+"${envs[@]}"} "$BASH_BIN" "$repo/scripts/build-runtime.sh" "$@") >"$OUT" 2>&1 || RC=$?
}
build() { sbuild -- "$@"; }

build linux-x86_64
t_check "a static x86_64 build succeeds" rc_is 0
t_check "it reports static" out_has "static: yes"
t_check "it prints the size" out_has "size: 10 bytes"
t_check "cargo ran with the strip config" grep -q -- "--config profile.release.strip=true" "$T_TMP/cargo.args"
t_check "cargo built the runtime for musl" grep -q -- "-p lunepack-runtime --target x86_64-unknown-linux-musl" "$T_TMP/cargo.args"

rm -rf "$repo/target"
sbuild CARGO_TARGET_DIR="$T_TMP/elsewhere" -- linux-x86_64
t_check "CARGO_TARGET_DIR is honoured by the check and the size" out_has "size: "
t_check "the build went to it" test -f "$T_TMP/elsewhere/x86_64-unknown-linux-musl/release/lunepack-runtime"
rm -rf "$repo/target"
build linux-x86_64 --out "$T_TMP/runtime-copy"
t_check "--out succeeds" rc_is 0
t_check "--out copies the binary" test -f "$T_TMP/runtime-copy"

rm -rf "$repo/target"
build linux-x86_64 --out "$T_TMP/no-such-dir/runtime-copy"
t_check "--out into a missing directory is refused" rc_nonzero
t_check "and nothing was built" test ! -e "$repo/target"

build linux-x86_64 --out
t_check "--out without a value is a usage error" rc_is 2

build linux-x86_64 --out "$T_TMP/a" --out "$T_TMP/b"
t_check "--out twice is a usage error" rc_is 2

build linux-x86_64 --out ""
t_check "an empty --out is a usage error" rc_is 2

rm -rf "$repo/target"
rm -f "$stubs/musl-gcc"
build linux-x86_64
t_check "no musl-gcc and no CC_<triple> is refused" rc_nonzero
t_check "it names musl-gcc" out_has "musl-gcc is not on PATH"
t_check "and cargo did not run" test ! -e "$repo/target"

stub clang 'exit 0'
sbuild CC_x86_64_unknown_linux_musl=clang -- linux-x86_64
t_check "CC_<triple> stands in for musl-gcc" rc_is 0

sbuild CC_x86_64_unknown_linux_musl=no-such-cc -- linux-x86_64
t_check "a CC_<triple> that is not on PATH is refused" rc_nonzero

stub musl-gcc 'exit 0'
rm -rf "$repo/target"
sbuild STUB_UNAME=x86_64 STUB_MACHINE=AArch64 -- linux-x86_64
t_check "a binary of the wrong machine is refused" rc_nonzero
t_check "the refusal names the machine" out_has "machine is not"

sbuild STUB_UNAME=x86_64 STUB_INTERP=1 -- linux-x86_64
t_check "a PT_INTERP binary is refused" rc_nonzero
t_check "the refusal names PT_INTERP" out_has "PT_INTERP"

sbuild STUB_NEEDED=1 -- linux-x86_64
t_check "a binary with NEEDED entries is refused" rc_nonzero
t_check "the refusal names NEEDED" out_has "NEEDED"

sbuild STUB_NOT_ELF=1 -- linux-x86_64
t_check "a file readelf rejects is refused" rc_nonzero

sbuild STUB_UNAME=aarch64 -- linux-x86_64
t_check "an aarch64 host needs CC_<triple> for x86_64" rc_nonzero
t_check "the refusal says which variable" out_has "CC_x86_64_unknown_linux_musl"

sbuild STUB_UNAME=arm64 STUB_MACHINE=AArch64 -- linux-aarch64
t_check "an arm64 host builds aarch64 with musl-gcc" rc_is 0

# --package builds another shipped binary by the same rules (M13 step 14).
rm -rf "$repo/target"
build linux-x86_64 --package lunepack-service
t_check "--package lunepack-service builds static for musl" rc_is 0
t_check "cargo built the service" grep -q -- "-p lunepack-service --target x86_64-unknown-linux-musl" "$T_TMP/cargo.args"
t_check "the check names the service" out_has "x86_64-unknown-linux-musl/release/lunepack-service"

rm -f "$stubs/readelf"
sbuild -- linux-x86_64
t_check "a missing readelf is refused before the build" rc_nonzero

# --- macOS targets, against stubs --------------------------------------------------------
stub lipo 'case "$1" in
  -archs)
    echo "${STUB_ARCHS:-arm64}"
    [ -z "${STUB_NOT_MACHO:-}" ]
    ;;
  -create)
    shift
    while [ "$#" -gt 0 ]; do
      if [ "$1" = -output ]; then o=$2; fi
      shift
    done
    printf "fat" >"$o"
    ;;
esac'
stub otool 'case "$1" in
  -L)
    echo "$2:"
    printf "%s\n" "${STUB_LIBS-$(printf "\t")/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)}"
    ;;
  -arch)
    case "$2" in
      x86_64) m=${STUB_MINOS_X86:-10.15} ;;
      *) m=${STUB_MINOS_ARM:-11.0} ;;
    esac
    echo "Load command 9"
    echo "      cmd LC_BUILD_VERSION"
    echo "  cmdsize 32"
    echo "    minos $m"
    ;;
esac'
# codesign: --verify of a slice says "not signed at all" under STUB_UNSIGNED until `-s` marks it,
# fails otherwise under STUB_BADSIG; --verify --strict answers STUB_STRICT_RC. Calls are logged.
stub codesign 'echo "codesign $*" >>"$CODESIGN_LOG"
for a in "$@"; do f=$a; done
case "$1" in
  -s) : >"$f.signed" ;;
  --verify)
    if [ "$2" = --strict ]; then exit "${STUB_STRICT_RC:-0}"; fi
    if [ -n "${STUB_BADSIG:-}" ]; then echo "$f: invalid signature (code or signature have been modified)" >&2; exit 1; fi
    if [ -n "${STUB_UNSIGNED:-}" ] && [ ! -e "$f.signed" ]; then echo "$f: code object is not signed at all" >&2; exit 1; fi
    ;;
esac
exit 0'
CODESIGN_LOG=$T_TMP/codesign.log
export CODESIGN_LOG
tab=$(printf '\t')

rm -rf "$repo/target"
sbuild STUB_OS=Darwin STUB_ARCHS=arm64 -- macos-aarch64
t_check "a macos-aarch64 build succeeds" rc_is 0
t_check "it reports a Mach-O of system libraries" out_has "macho: yes (arm64; system libraries only)"
t_check "it reports the minimum macOS" out_has "minos: arm64=11.0"
t_check "it prints the size" out_has "size: 10 bytes"
t_check "cargo built for the Apple triple" grep -q -- "--target aarch64-apple-darwin" "$T_TMP/cargo.args"
t_check "with the deployment target set" grep -q -- "^MACOSX_DEPLOYMENT_TARGET=10.15 build --locked --release -p lunepack-runtime" "$T_TMP/cargo.args"
t_check "and the strip config" grep -q -- "--config profile.release.strip=true" "$T_TMP/cargo.args"

rm -rf "$repo/target"
: >"$CODESIGN_LOG"
sbuild STUB_OS=Darwin STUB_ARCHS=x86_64 -- macos-x86_64
t_check "a macos-x86_64 build succeeds" rc_is 0
t_check "its minimum is the deployment target" out_has "minos: x86_64=10.15"
t_check "it reports the ad-hoc signature" out_has "signature: ad hoc on every slice"
t_check "a slice the linker signed is not signed again" test "$(grep -c -- '^codesign -s' "$CODESIGN_LOG" || true)" -eq 0
t_check "the result was verified strictly on every slice" grep -q -- "^codesign --verify --strict --all-architectures" "$CODESIGN_LOG"

rm -rf "$repo/target"
: >"$CODESIGN_LOG"
sbuild STUB_OS=Darwin STUB_ARCHS=x86_64 STUB_UNSIGNED=1 -- macos-x86_64
t_check "an unsigned x86_64 slice is signed ad hoc and the build succeeds" rc_is 0
t_check "with the linker's kind of signature and no identity" grep -q -- "^codesign -s - -o linker-signed target/x86_64-apple-darwin/release/lunepack-runtime" "$CODESIGN_LOG"

sbuild STUB_OS=Darwin STUB_ARCHS=x86_64 STUB_BADSIG=1 -- macos-x86_64
t_check "a slice whose signature does not verify is refused" rc_nonzero
t_check "the refusal says codesign --verify failed" out_has "codesign --verify failed"

sbuild STUB_OS=Darwin STUB_ARCHS=x86_64 STUB_STRICT_RC=1 -- macos-x86_64
t_check "a result that fails codesign --verify --strict is refused" rc_nonzero
t_check "the refusal names the strict check" out_has "does not pass codesign --verify --strict"

sbuild STUB_OS=Darwin STUB_ARCHS=x86_64 STUB_MINOS_X86=10.12 -- macos-x86_64
t_check "an x86_64 slice with a lower minimum is refused" rc_nonzero
t_check "the refusal names the minimum" out_has "needs macOS 10.12"

sbuild STUB_OS=Darwin STUB_ARCHS=x86_64 STUB_MINOS_X86=11.0 -- macos-x86_64
t_check "an x86_64 slice with a higher minimum is refused" rc_nonzero

rm -rf "$repo/target"
sbuild STUB_OS=Darwin 'STUB_ARCHS=x86_64 arm64' -- macos-universal
t_check "a macos-universal build succeeds" rc_is 0
t_check "it reports both slices" out_has "macho: yes (x86_64 arm64; system libraries only)"
t_check "with both minimums" out_has "minos: x86_64=10.15 arm64=11.0"
t_check "both Apple triples were built" test "$(grep -c -- "--target" "$T_TMP/cargo.args")" -eq 2
t_check "the aarch64 build ran" grep -q -- "--target aarch64-apple-darwin" "$T_TMP/cargo.args"
t_check "the x86_64 build ran" grep -q -- "--target x86_64-apple-darwin" "$T_TMP/cargo.args"
t_check "every build had the deployment target" test "$(grep -c -- "^MACOSX_DEPLOYMENT_TARGET=10.15 " "$T_TMP/cargo.args")" -eq 2
t_check "lipo wrote the universal binary" test -f "$repo/target/universal-apple-darwin/release/lunepack-runtime"
t_check "the check names it" out_has "universal-apple-darwin/release/lunepack-runtime"

sbuild STUB_OS=Darwin STUB_ARCHS=arm64 -- macos-universal
t_check "a universal binary with one slice is refused" rc_nonzero
t_check "the refusal names both lists" out_has "holds the architectures [arm64], not [arm64 x86_64]"

sbuild STUB_OS=Darwin STUB_ARCHS=x86_64 -- macos-aarch64
t_check "a binary of the wrong architecture is refused" rc_nonzero
t_check "the refusal names the architecture" out_has "not [arm64]"

sbuild STUB_OS=Darwin "STUB_LIBS=${tab}/opt/homebrew/lib/libfoo.dylib (compatibility version 1.0.0)" -- macos-aarch64
t_check "a non-system library is refused" rc_nonzero
t_check "the refusal names it" out_has "links /opt/homebrew/lib/libfoo.dylib"

sbuild STUB_OS=Darwin STUB_LIBS= -- macos-aarch64
t_check "an otool that lists no library is refused" rc_nonzero
t_check "the refusal says so" out_has "listed no libraries"

sbuild STUB_OS=Darwin STUB_NOT_MACHO=1 -- macos-aarch64
t_check "a file lipo rejects is refused" rc_nonzero

sbuild -- macos-aarch64
t_check "a macOS target on another host is refused" rc_nonzero
t_check "the refusal names the host" out_has "macOS host only"
t_check "and cargo did not run" test ! -e "$T_TMP/cargo.args"

mv "$stubs/codesign" "$stubs/codesign.off"
sbuild STUB_OS=Darwin -- macos-aarch64
t_check "a missing codesign is refused before the build" rc_nonzero
t_check "the refusal names codesign" out_has "codesign is not on PATH"
mv "$stubs/codesign.off" "$stubs/codesign"

# --package builds another shipped binary by the same rules.
rm -rf "$repo/target"
sbuild STUB_OS=Darwin 'STUB_ARCHS=x86_64 arm64' -- macos-universal --package lunepack-ui
t_check "--package lunepack-ui builds a universal UI on macOS" rc_is 0
t_check "lipo joined the UI" test -f "$repo/target/universal-apple-darwin/release/lunepack-ui"
build linux-x86_64 --package lunepack-ui
t_check "--package lunepack-ui on Linux is a usage error" rc_is 2
t_check "it says the UI is macOS only here" out_has "macOS targets only"
build linux-x86_64 --package lunepack-cli
t_check "an unknown --package is a usage error" rc_is 2
build linux-x86_64 --package lunepack-service --package lunepack-runtime
t_check "--package twice is a usage error" rc_is 2
run_cmd bash "$SCRIPT" --print-command macos-universal --package lunepack-ui
t_check "--print-command follows --package" out_has "lipo -create -output target/universal-apple-darwin/release/lunepack-ui"

rm -f "$stubs/lipo"
sbuild STUB_OS=Darwin -- macos-aarch64
t_check "a missing lipo is refused before the build" rc_nonzero
t_check "the refusal names lipo" out_has "lipo is not on PATH"
t_check "and cargo did not run before it" test ! -e "$T_TMP/cargo.args"

rm -rf "$repo/target"
stub lipo 'echo arm64'
sbuild STUB_OS=Darwin -- macos-aarch64 --out "$T_TMP/macos-runtime"
t_check "--out works for a macOS build" rc_is 0
t_check "--out copied the binary" test -f "$T_TMP/macos-runtime"


t_finish
