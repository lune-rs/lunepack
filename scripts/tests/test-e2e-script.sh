#!/usr/bin/env bash
# Tests for the argument handling of scripts/e2e.sh and scripts/e2e-macos.sh. Nothing here starts
# Docker or a suite: only invalid arguments, --help, the refusals off the suite's own OS, and the
# Docker mode's handling of the .NET example against a stub docker and a stub dotnet.
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
  if [ "$1" = -o ]; then out=$2; fi
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

t_finish
