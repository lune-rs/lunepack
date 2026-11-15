#!/usr/bin/env bash
# The end-to-end suite of the Linux runtime (M5-D13): installs an app from a bootstrap tree,
# updates it through the static runtime, rolls back what does not confirm, and uninstalls it.
# It is not part of the gate (scripts/gate.sh).
#
#   scripts/e2e.sh                          run the suite in a Docker container (the usual way)
#   scripts/e2e.sh --inside [--runtime <p>] run it here: the container's own entry and the CI job.
#                                           Refuses off Linux and outside a container or CI.
#
# Inside, it builds the static musl runtime (scripts/build-runtime.sh; or takes --runtime), the
# `lunepack` command line and the Rust example app, then runs the test binary
# crates/lunepack-runtime/tests/e2e with them. LUNEPACK_E2E_REQUIRE=1 is set, so a missing piece
# fails instead of skipping.
#
# The Docker mode builds the image `lunepack-rs-e2e:<hash>` from scripts/e2e.Dockerfile (once per
# Dockerfile change), runs `docker run --rm --init` (a reaping PID 1, as on a desktop) with the
# worktree read-only, and keeps its build output in two named volumes of its own
# (lunepack-rs-e2e-target, lunepack-rs-e2e-cargo). It never prunes and never touches other
# containers, images or volumes. bash 3.2 compatible.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: scripts/e2e.sh [--inside [--runtime <path>]]" >&2
}

die() {
  echo "e2e: $*" >&2
  exit 1
}

inside=0
runtime=
while [ "$#" -gt 0 ]; do
  case $1 in
    --inside)
      inside=1
      shift
      ;;
    --runtime)
      [ "$#" -ge 2 ] && [ -n "$2" ] || {
        usage
        exit 2
      }
      runtime=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done
if [ -n "$runtime" ] && [ "$inside" -eq 0 ]; then
  usage
  exit 2
fi

if [ "$inside" -eq 0 ]; then
  command -v docker >/dev/null 2>&1 || die "docker is not installed"
  docker info >/dev/null 2>&1 || die "the Docker daemon is not running"
  dockerfile=scripts/e2e.Dockerfile
  if command -v shasum >/dev/null 2>&1; then
    hash=$(shasum -a 256 "$dockerfile" | cut -c 1-12)
  else
    hash=$(sha256sum "$dockerfile" | cut -c 1-12)
  fi
  image=lunepack-rs-e2e:$hash
  if docker image inspect "$image" >/dev/null 2>&1; then
    echo "e2e: using docker image $image"
  else
    echo "e2e: building docker image $image from $dockerfile"
    docker build --quiet -t "$image" - <"$dockerfile" >/dev/null
  fi
  # RUSTUP_TOOLCHAIN makes rustup use the image's own 1.99.1 instead of installing what
  # rust-toolchain.toml lists. No host env is passed, no capabilities, no new privileges.
  exec docker run --rm --init \
    --name "lunepack-rs-e2e-$$" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    -v "$top":/src:ro \
    -v lunepack-rs-e2e-target:/target \
    -v lunepack-rs-e2e-cargo:/cargo-home \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_HOME=/cargo-home \
    -e RUSTUP_TOOLCHAIN=1.99.1 \
    -w /src \
    "$image" \
    ./scripts/e2e.sh --inside
fi

# --- inside -----------------------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "refusing to run: the suite is Linux only (run scripts/e2e.sh for Docker)"
if [ ! -e /.dockerenv ] && [ ! -e /run/.containerenv ] && [ -z "${CI:-}" ]; then
  die "refusing to run outside a container or CI (run scripts/e2e.sh for Docker)"
fi
case $(uname -m) in
  x86_64) target=linux-x86_64 ;;
  aarch64 | arm64) target=linux-aarch64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
tdir=${CARGO_TARGET_DIR:-$top/target}

work=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-e2e-build.XXXXXX")
cleanup() {
  # Only the directory created above.
  rm -rf "$work"
}
trap cleanup EXIT

if [ -z "$runtime" ]; then
  echo "e2e: building the static runtime for $target"
  ./scripts/build-runtime.sh "$target" --out "$work/lunepack-runtime"
  runtime=$work/lunepack-runtime
fi
[ -f "$runtime" ] || die "the runtime is not a file"

echo "e2e: building the lunepack command line and the example app"
cargo build --locked --release -p lunepack-cli
cargo build --locked --release -p lunepack --example e2e_app
# A stripped copy: the app is packed once per release, and its size is the pack's.
strip -o "$work/e2e_app" "$tdir/release/examples/e2e_app"

LUNEPACK_E2E_RUNTIME=$runtime \
  LUNEPACK_E2E_CLI=$tdir/release/lunepack \
  LUNEPACK_E2E_APP=$work/e2e_app \
  LUNEPACK_E2E_REQUIRE=1 \
  cargo test --locked -p lunepack-runtime --test e2e
