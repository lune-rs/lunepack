#!/usr/bin/env bash
# Tests for the argument handling of scripts/e2e.sh and scripts/e2e-macos.sh. Nothing here starts
# Docker or a suite: only invalid arguments, --help, the refusals off the suite's own OS, and the
# Docker mode's handling of the .NET example against a stub docker and a stub dotnet, and the C
# example's opt-out in the Docker mode and its build in the inside mode (stub cargo, strip, cc).
# SC2016: the stub bodies are scripts, and `bash -c '...' _ args` keeps its program in single quotes.
# shellcheck disable=SC2016
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

# --- the .NET example in the Docker mode (M13 step 7), against a stub docker and a stub dotnet -----
# The PATH holds a stub docker and symlinks to the few tools the scripts use: no other dotnet.
BASH_BIN=$(command -v bash)
stubs=$T_TMP/stubs
mkdir -p "$stubs" "$T_TMP/tmp"
for tool in dirname cut mktemp rm env bash ls find wc tr cat mkdir cp uname id shasum sha256sum; do
  if command -v "$tool" >/dev/null 2>&1; then ln -s "$(command -v "$tool")" "$stubs/$tool"; fi
done
printf '#!/bin/sh\n%s\n' 'case $1 in
  image)
    if [ "$2" = inspect ] && [ "$3" = --format ]; then echo "${STUB_ARCH:-arm64}"; fi
    exit 0 ;;
  run) echo "$@" >"$STUB_LOG"; exit "${STUB_RUN_RC:-0}" ;;
  *) exit 0 ;;
esac' >"$stubs/docker"
chmod 755 "$stubs/docker"
stub_dotnet() { # a dotnet that writes the files of a publish into its -o directory
  printf '#!/bin/sh\n%s\n' 'echo "$@" >>"$STUB_DOTNET_LOG"
while [ "$#" -gt 0 ]; do
  case $1 in -p:PublishDir=*) out=${1#-p:PublishDir=} ;; esac
  shift
done
mkdir -p "$out"
echo exe >"$out/Example"
echo dll >"$out/Example.dll"' >"$stubs/dotnet"
  chmod 755 "$stubs/dotnet"
}
docker_mode() { # env assignments..., run in the docker mode with the stub PATH
  RC=0
  rm -f "$T_TMP/docker.args" "$T_TMP/dotnet.args"
  env -i HOME="$T_TMP" TMPDIR="$T_TMP/tmp" PATH="$stubs" STUB_LOG="$T_TMP/docker.args" \
    STUB_DOTNET_LOG="$T_TMP/dotnet.args" "$@" "$BASH_BIN" "$SCRIPT" >"$OUT" 2>&1 || RC=$?
}

docker_mode LUNEPACK_E2E_X=1
t_check "without dotnet the Docker mode fails" rc_is 1
t_check "and says dotnet is not installed" out_has "dotnet is not installed"
t_check "and how to skip the .NET rows" out_has "LUNEPACK_E2E_DOTNET=0"
t_check "the container never started" test ! -e "$T_TMP/docker.args"

docker_mode LUNEPACK_E2E_DOTNET=0
t_check "the opt-out runs without dotnet" rc_is 0
t_check "the container is told the opt-out" grep -qF -- "-e LUNEPACK_E2E_DOTNET=0" "$T_TMP/docker.args"
t_check "and gets no .NET folder" bash -c '! grep -q dotnet-app "$1"' _ "$T_TMP/docker.args"

stub_dotnet
docker_mode LUNEPACK_E2E_X=1
t_check "with dotnet the Docker mode runs" rc_is 0
t_check "it published for the image's architecture (arm64)" grep -q -- "-r linux-arm64 " "$T_TMP/dotnet.args"
t_check "the container gets the folder read-only" grep -q -- ":/dotnet-app:ro" "$T_TMP/docker.args"
t_check "and its name" grep -qF -- "-e LUNEPACK_E2E_DOTNET_APP=/dotnet-app" "$T_TMP/docker.args"
t_check "the run's temporary directory is removed when it ends" test -z "$(ls -A "$T_TMP/tmp")"

docker_mode STUB_ARCH=amd64
t_check "an amd64 image publishes for linux-x64" grep -q -- "-r linux-x64 " "$T_TMP/dotnet.args"

docker_mode STUB_ARCH=riscv
t_check "an architecture it does not know is refused" rc_is 1

docker_mode STUB_RUN_RC=7
t_check "the container's exit code is the script's" rc_is 7
t_check "its temporary directory is removed after a failure too" test -z "$(ls -A "$T_TMP/tmp")"

# --- the C example (M14 step 6): the opt-out the Docker mode hands over, and the inside build -------
docker_mode LUNEPACK_E2E_DOTNET=0
t_check "the container is told the C rows run by default" grep -qF -- "-e LUNEPACK_E2E_C=1" "$T_TMP/docker.args"

docker_mode LUNEPACK_E2E_DOTNET=0 LUNEPACK_E2E_C=0
t_check "the C opt-out runs" rc_is 0
t_check "the container is told the C opt-out" grep -qF -- "-e LUNEPACK_E2E_C=0" "$T_TMP/docker.args"
t_check "and not that the C rows run" bash -c '! grep -qF -- "-e LUNEPACK_E2E_C=1" "$1"' _ "$T_TMP/docker.args"

docker_mode LUNEPACK_E2E_DOTNET=0 LUNEPACK_E2E_C=banana
t_check "any value but 0 leaves the C rows on" grep -qF -- "-e LUNEPACK_E2E_C=1" "$T_TMP/docker.args"
t_check "and the host's own text never crosses" bash -c '! grep -q banana "$1"' _ "$T_TMP/docker.args"

# The inside mode, as the container and the CI job run it, against stubs: a Linux uname, an
# unprivileged id, a cargo that records its arguments (and makes the C folder when xtask is asked),
# a strip, and, in the first cases, a cc. CI=1 stands in for the container.
istubs=$T_TMP/istubs
mkdir -p "$istubs" "$T_TMP/itmp"
for tool in dirname mktemp rm env bash cat mkdir grep sort ls; do
  if command -v "$tool" >/dev/null 2>&1; then ln -s "$(command -v "$tool")" "$istubs/$tool"; fi
done
printf '#!/bin/sh\n%s\n' 'case $1 in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac' >"$istubs/uname"
printf '#!/bin/sh\n%s\n' 'echo 1000' >"$istubs/id"
printf '#!/bin/sh\n%s\n' 'if [ "$1" = -o ]; then echo stripped >"$2"; fi' >"$istubs/strip"
printf '#!/bin/sh\n%s\n' 'echo "$@" >>"$STUB_CARGO_LOG"
case $1 in
  run)
    while [ "$#" -gt 0 ]; do
      case $1 in --out) out=$2 ;; esac
      shift
    done
    mkdir -p "$out"
    echo exe >"$out/example" ;;
  test)
    env | grep "^LUNEPACK_E2E_" | sort >"$STUB_ENV_LOG"
    if [ -n "${LUNEPACK_E2E_C_APP:-}" ] && [ -f "$LUNEPACK_E2E_C_APP/example" ]; then echo "c-entry present" >>"$STUB_ENV_LOG"; fi ;;
esac' >"$istubs/cargo"
printf '#!/bin/sh\n%s\n' 'exit 0' >"$istubs/cc"
chmod 755 "$istubs/uname" "$istubs/id" "$istubs/strip" "$istubs/cargo" "$istubs/cc"
echo runtime >"$T_TMP/runtime-file"
inside_mode() { # env assignments..., run `--inside` with the stub PATH (a cc is on it unless NO_CC=1)
  RC=0
  rm -f "$T_TMP/cargo.args" "$T_TMP/suite.env"
  rm -rf "$T_TMP/itmp"
  mkdir -p "$T_TMP/itmp"
  if [ "${NO_CC:-0}" = 1 ]; then mv "$istubs/cc" "$istubs/cc.off"; fi
  env -i HOME="$T_TMP" TMPDIR="$T_TMP/itmp" PATH="$istubs" CI=1 LUNEPACK_E2E_DOTNET=0 \
    STUB_CARGO_LOG="$T_TMP/cargo.args" STUB_ENV_LOG="$T_TMP/suite.env" \
    "$@" "$BASH_BIN" "$SCRIPT" --inside --runtime "$T_TMP/runtime-file" >"$OUT" 2>&1 || RC=$?
  if [ -e "$istubs/cc.off" ]; then mv "$istubs/cc.off" "$istubs/cc"; fi
}

inside_mode LUNEPACK_E2E_X=1
t_check "inside, the suite runs" rc_is 0
t_check "it builds the C example with xtask" grep -qF -- "run --quiet --locked -p xtask -- build-example-c --out" "$T_TMP/cargo.args"
t_check "for the suite's own target" grep -qF -- "--target linux-x86_64" "$T_TMP/cargo.args"
t_check "it hands the suite the built folder" grep -q "^LUNEPACK_E2E_C_APP=.*/c-app$" "$T_TMP/suite.env"
t_check "which holds the entry when the suite starts" grep -qF "c-entry present" "$T_TMP/suite.env"
t_check "and says it is building" out_has "building the C example for linux-x86_64"
t_check "the build directory is removed when the run ends" test -z "$(ls -A "$T_TMP/itmp")"

inside_mode LUNEPACK_E2E_C=0
t_check "the C opt-out runs the suite" rc_is 0
t_check "it builds no C example" bash -c '! grep -q build-example-c "$1"' _ "$T_TMP/cargo.args"
t_check "it hands the suite no C folder" bash -c '! grep -q "^LUNEPACK_E2E_C_APP=" "$1"' _ "$T_TMP/suite.env"
t_check "and tells the suite the opt-out (which prints SKIPPED)" grep -qF "LUNEPACK_E2E_C=0" "$T_TMP/suite.env"

NO_CC=1 inside_mode LUNEPACK_E2E_X=1
t_check "without a C compiler the suite fails" rc_is 1
t_check "and says no C compiler" out_has "no C compiler"
t_check "and how to skip the C rows" out_has "LUNEPACK_E2E_C=0"
t_check "the suite never started" test ! -e "$T_TMP/suite.env"

mkdir -p "$T_TMP/handed/c" "$T_TMP/handed/empty"
echo exe >"$T_TMP/handed/c/example"
inside_mode LUNEPACK_E2E_C_APP="$T_TMP/handed/c"
t_check "a folder handed in is used" rc_is 0
t_check "without building" bash -c '! grep -q build-example-c "$1"' _ "$T_TMP/cargo.args"
t_check "and passed on as it is" grep -qF "LUNEPACK_E2E_C_APP=$T_TMP/handed/c" "$T_TMP/suite.env"

inside_mode LUNEPACK_E2E_C_APP="$T_TMP/handed/empty"
t_check "a handed-in folder with no entry is refused" rc_is 1
t_check "naming the variable" out_has "LUNEPACK_E2E_C_APP does not name a built folder"
t_check "the suite never started on it" test ! -e "$T_TMP/suite.env"

t_finish
