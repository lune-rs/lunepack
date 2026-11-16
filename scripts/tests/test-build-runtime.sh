#!/usr/bin/env bash
# Tests for scripts/build-runtime.sh. Nothing here runs the real cargo: a valid target is given with
# --print-command, or the build runs in a scratch copy of the script with stub cargo, readelf,
# uname and musl-gcc on a PATH that holds nothing else but cp, wc and mkdir.
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

# --- the build path, against stubs --------------------------------------------------------
BASH_BIN=$(command -v bash)
repo=$T_TMP/repo
stubs=$T_TMP/stubs
mkdir -p "$repo/scripts" "$stubs"
cp "$SCRIPT" "$repo/scripts/build-runtime.sh"
for tool in cp wc mkdir; do
  ln -s "$(command -v "$tool")" "$stubs/$tool"
done
stub() { # name, body (a /bin/sh script)
  printf '#!/bin/sh\n%s\n' "$2" >"$stubs/$1"
  chmod +x "$stubs/$1"
}
stub uname 'echo "${STUB_UNAME:-x86_64}"'
stub musl-gcc 'exit 0'
stub cargo 'echo "$@" >"$STUB_LOG"
while [ "$#" -gt 0 ]; do
  if [ "$1" = --target ]; then t=$2; fi
  shift
done
d=${CARGO_TARGET_DIR:-target}/$t/release
mkdir -p "$d"
printf "0123456789" >"$d/lunepack-runtime"'
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

rm -f "$stubs/readelf"
sbuild -- linux-x86_64
t_check "a missing readelf is refused before the build" rc_nonzero

t_finish
