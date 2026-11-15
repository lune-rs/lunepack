#!/usr/bin/env bash
# Builds the static lunepack runtime for a Linux target (M5-D7). `lunepack pack --runtime <path>`
# places the result beside the app's entry. Run from anywhere; builds from the repo top level.
#
#   scripts/build-runtime.sh <linux-x86_64|linux-aarch64>
#   scripts/build-runtime.sh --print-command <target>   # print the build command, run nothing
#
# The musl target must be installed (`rustup target add <triple>`); this script installs nothing.
# Step 10 of M5 adds the size profile, the CI job and the size record.
set -euo pipefail

usage() {
  echo "usage: ${0##*/} [--print-command] <linux-x86_64|linux-aarch64>" >&2
}

print_only=0
if [ "${1:-}" = "--print-command" ]; then
  print_only=1
  shift
fi
if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

case $1 in
  linux-x86_64) triple=x86_64-unknown-linux-musl ;;
  linux-aarch64) triple=aarch64-unknown-linux-musl ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "${0##*/}: unknown target (only linux-x86_64 and linux-aarch64 are built here)" >&2
    usage
    exit 2
    ;;
esac

cmd=(cargo build --locked --release -p lunepack-runtime --target "$triple")
if [ "$print_only" -eq 1 ]; then
  echo "${cmd[*]}"
  exit 0
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
"${cmd[@]}"
echo "built: target/$triple/release/lunepack-runtime"
