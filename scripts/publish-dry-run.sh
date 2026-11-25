#!/usr/bin/env bash
# Dry run of the crates.io publication (M13-D5): packages the ten crates of the publish set, builds
# each package on its own and stops where the upload would start. Nothing is uploaded and no
# registry is contacted for writing; `--dry-run` is fixed in this script and nothing can remove it.
#
#   scripts/publish-dry-run.sh
#
# It refuses to start when a registry token is in the environment (`CARGO_REGISTRY_TOKEN` or any
# `CARGO_REGISTRIES_<name>_TOKEN`): a dry run needs none, so a set token is a mistake or a risk.
# It runs `cargo publish --workspace --dry-run --locked` from the repository root, shows cargo's
# output, then fails unless exactly the ten names of the set reach "Uploading" and each is followed
# by cargo's dry-run abort. It prints no environment variable, only the name of an offending one.
# Cargo needs a clean work tree (it refuses uncommitted changes), the network for the crates.io
# index, and the toolchain in `rust-toolchain.toml`. bash 3.2 compatible (D30).
set -euo pipefail

self=${0##*/}
here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
repo=$(cd "$here/.." && pwd)

# The publish set: the list `xtask check-boundaries` holds (PUBLISH_SET), sorted.
expected="lunepack
lunepack-cli
lunepack-codec-lzma
lunepack-core
lunepack-crypto
lunepack-fs
lunepack-http
lunepack-os-linux
lunepack-os-macos
lunepack-os-windows"

die() {
  echo "$self: $*" >&2
  exit 1
}

if [ "$#" -ne 0 ]; then
  case ${1:-} in
    -h | --help)
      echo "usage: $self" >&2
      echo "  dry run of 'cargo publish --workspace'; takes no arguments" >&2
      exit 0
      ;;
  esac
  echo "usage: $self (takes no arguments; --dry-run is fixed)" >&2
  exit 2
fi

# A registry token in the environment: name it, never its value.
for name in $(compgen -e); do
  case $name in
    CARGO_REGISTRY_TOKEN | CARGO_REGISTRIES_*_TOKEN)
      die "the environment variable $name is set; a dry run needs no token, unset it"
      ;;
  esac
done

log=$(mktemp "${TMPDIR:-/tmp}/lunepack-publish.XXXXXX")
trap 'rm -f "$log"' EXIT

cd "$repo"
echo "$self: cargo publish --workspace --dry-run --locked" >&2
rc=0
CARGO_TERM_COLOR=never cargo publish --workspace --dry-run --locked 2>&1 | tee "$log" || rc=$?
# `pipefail` (set above) makes the pipeline's status cargo's, not tee's.
if [ "$rc" -ne 0 ]; then
  die "cargo publish --dry-run failed (exit $rc)"
fi

# Each "Uploading <name> v<version> (...)" line must be followed at once by the dry-run abort.
found=$(awk '
  /^ *Uploading [^ ]+ v[^ ]+/ {
    if (pending != "") { bad = bad " " pending }
    pending = $2
    next
  }
  pending != "" {
    if ($0 ~ /^warning: aborting upload due to dry run$/) { print pending; pending = ""; next }
    bad = bad " " pending
    pending = ""
  }
  END {
    if (pending != "") { bad = bad " " pending }
    if (bad != "") { print "!" bad }
  }
' "$log")

case $found in
  *'!'*) die "no dry-run abort followed the upload of:${found#*!}" ;;
esac
sorted=$(printf '%s\n' "$found" | sort)
if [ "$sorted" != "$expected" ]; then
  echo "$self: the crates that reached the upload are not the publish set" >&2
  echo "expected:" >&2
  printf '%s\n' "$expected" | sed 's/^/  /' >&2
  echo "got:" >&2
  printf '%s\n' "$sorted" | sed 's/^/  /' >&2
  exit 1
fi
echo "$self: ok (10 crates reached the dry-run abort)" >&2
