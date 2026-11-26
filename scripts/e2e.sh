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
# `lunepack` command line, the Rust example app, the stand-in UI (a small executable that speaks the
# frame protocol with no window, tests/e2e/fake-ui) and the real `lunepack-ui`, then runs the test
# binary crates/lunepack-runtime/tests/e2e with them and with the shell app
# (tests/e2e/shell-app/app.sh, checked with shellcheck when that is installed). The scenario table
# and the UI table (setup files, a UI that is absent or killed) run once per app and the two
# outcome logs of each must be equal; the command-line and UI extras run after. No scenario needs a
# GPU or a display: the real UI is only started with a DISPLAY that nothing serves, to see it exit
# with its typed code. LUNEPACK_E2E_REQUIRE=1 is set, so a missing piece fails instead of skipping.
#
# The .NET example (examples/dotnet, M13 step 7) runs a third table: a folder of about 190 files that
# is published self-contained by scripts/build-example-dotnet.sh for the suite's own Linux target,
# on the host in the Docker mode (the container has no .NET SDK; it gets the folder read-only) and
# natively with `--inside` when no folder was handed in (the CI job installs .NET first). Its
# outcome log must equal the shell app's, cut to the rows it runs (scenarios.rs, FOLDER_APP_ROWS).
# `dotnet` missing is a failure; LUNEPACK_E2E_DOTNET=0 is the one opt-out, and the suite then prints
# SKIPPED once.
#
# The C example (examples/c, M14 step 6) runs a fourth table the same way: the app and the C library
# beside it, built inside the container by `cargo run -p xtask -- build-example-c` for the suite's own
# Linux target (the image has the C compiler), and its outcome log must equal the shell app's, cut to
# the same rows. A missing C compiler is a failure; LUNEPACK_E2E_C=0 is the one opt-out (the Docker
# mode hands it to the container), and the suite then prints SKIPPED once.
#
# The Docker mode builds the image `lunepack-rs-e2e:<hash>` from scripts/e2e.Dockerfile (once per
# Dockerfile change), runs `docker run --rm --init` (a reaping PID 1, as on a desktop) with the
# worktree read-only, as the image's unprivileged user `e2e` (a setup run as root without
# `--all-users` is refused by design, M11-D9, and a root run would hide a regression behind that
# refusal), and keeps its build output in two named volumes of its own, owned by that user
# (lunepack-rs-e2e-user-target, lunepack-rs-e2e-user-cargo: not the root-owned
# lunepack-rs-e2e-target and -cargo of scripts/e2e-linux-machine.sh's build step). It never prunes
# and never touches other containers, images or volumes. bash 3.2 compatible.
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
  # The .NET example, published here for the container's architecture (the image has no .NET
  # SDK) into a directory of this run's own, which the container gets read-only.
  dotnet_args=(-e LUNEPACK_E2E_DOTNET=0)
  host_work=
  # Run by the EXIT trap below.
  # shellcheck disable=SC2329
  host_cleanup() {
    # Only the directory made below.
    if [ -n "$host_work" ]; then rm -rf "$host_work"; fi
  }
  trap host_cleanup EXIT
  trap 'exit 130' INT TERM
  if [ "${LUNEPACK_E2E_DOTNET:-1}" != 0 ]; then
    command -v dotnet >/dev/null 2>&1 || die "dotnet is not installed: the .NET rows need the SDK of examples/dotnet/global.json (LUNEPACK_E2E_DOTNET=0 skips them)"
    case $(docker image inspect --format '{{.Architecture}}' "$image") in
      arm64) dotnet_target=linux-aarch64 ;;
      amd64) dotnet_target=linux-x86_64 ;;
      *) die "unsupported image architecture" ;;
    esac
    host_work=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-e2e-dotnet.XXXXXX")
    echo "e2e: publishing the .NET example for $dotnet_target"
    ./scripts/build-example-dotnet.sh "$dotnet_target" "$host_work/app"
    dotnet_args=(-v "$host_work/app":/dotnet-app:ro -e LUNEPACK_E2E_DOTNET_APP=/dotnet-app)
  fi
  # The C example is built inside the container: only its opt-out crosses (0 or 1, never the host's
  # own text).
  c_args=(-e LUNEPACK_E2E_C=1)
  if [ "${LUNEPACK_E2E_C:-1}" = 0 ]; then c_args=(-e LUNEPACK_E2E_C=0); fi
  # RUSTUP_TOOLCHAIN makes rustup use the image's own 1.99.1 instead of installing what
  # rust-toolchain.toml lists. No host env is passed (but the two opt-outs above), no capabilities,
  # no new privileges; the suite runs as the image's user `e2e`, uid 1000, never as root.
  rc=0
  docker run --rm --init \
    --name "lunepack-rs-e2e-$$" \
    --user 1000:1000 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    -v "$top":/src:ro \
    -v lunepack-rs-e2e-user-target:/target \
    -v lunepack-rs-e2e-user-cargo:/cargo-home \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_HOME=/cargo-home \
    -e RUSTUP_TOOLCHAIN=1.99.1 \
    "${dotnet_args[@]}" \
    "${c_args[@]}" \
    -w /src \
    "$image" \
    ./scripts/e2e.sh --inside || rc=$?
  exit "$rc"
fi

# --- inside -----------------------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "refusing to run: the suite is Linux only (run scripts/e2e.sh for Docker)"
if [ ! -e /.dockerenv ] && [ ! -e /run/.containerenv ] && [ -z "${CI:-}" ]; then
  die "refusing to run outside a container or CI (run scripts/e2e.sh for Docker)"
fi
[ "$(id -u)" != 0 ] || die "refusing to run as root: the setup rows need an unprivileged user (M11-D9)"
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

echo "e2e: building the lunepack command line, the example app and the UIs"
cargo build --locked --release -p lunepack-cli
cargo build --locked --release -p lunepack --example e2e_app
cargo build --locked --release -p lunepack-runtime --example e2e_fake_ui
cargo build --locked --release -p lunepack-ui
# A stripped copy: each is packed with the releases, and its size is the pack's.
strip -o "$work/e2e_app" "$tdir/release/examples/e2e_app"
strip -o "$work/e2e_fake_ui" "$tdir/release/examples/e2e_fake_ui"
strip -o "$work/lunepack-ui" "$tdir/release/lunepack-ui"

# The .NET example: a folder handed in (the Docker mode), the opt-out, or published here.
if [ "${LUNEPACK_E2E_DOTNET:-1}" = 0 ]; then
  unset LUNEPACK_E2E_DOTNET_APP
elif [ -n "${LUNEPACK_E2E_DOTNET_APP:-}" ]; then
  [ -f "$LUNEPACK_E2E_DOTNET_APP/Example" ] || die "LUNEPACK_E2E_DOTNET_APP does not name a published folder of the .NET example"
else
  command -v dotnet >/dev/null 2>&1 || die "dotnet is not installed: the .NET rows need the SDK of examples/dotnet/global.json (LUNEPACK_E2E_DOTNET=0 skips them)"
  echo "e2e: publishing the .NET example for $target"
  ./scripts/build-example-dotnet.sh "$target" "$work/dotnet-app"
  export LUNEPACK_E2E_DOTNET_APP=$work/dotnet-app
fi

# The C example: a folder handed in, the opt-out, or built here (the app and the C library beside
# it, for the suite's own target).
if [ "${LUNEPACK_E2E_C:-1}" = 0 ]; then
  unset LUNEPACK_E2E_C_APP
elif [ -n "${LUNEPACK_E2E_C_APP:-}" ]; then
  [ -f "$LUNEPACK_E2E_C_APP/example" ] || die "LUNEPACK_E2E_C_APP does not name a built folder of the C example"
else
  command -v cc >/dev/null 2>&1 || die "no C compiler (cc): the C rows need one (LUNEPACK_E2E_C=0 skips them)"
  echo "e2e: building the C example for $target"
  cargo run --quiet --locked -p xtask -- build-example-c --out "$work/c-app" --target "$target"
  export LUNEPACK_E2E_C_APP=$work/c-app
fi

shell_app=$top/crates/lunepack-runtime/tests/e2e/shell-app/app.sh
[ -f "$shell_app" ] || die "the shell app is missing"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s sh "$shell_app"
fi

LUNEPACK_E2E_RUNTIME=$runtime \
  LUNEPACK_E2E_CLI=$tdir/release/lunepack \
  LUNEPACK_E2E_APP=$work/e2e_app \
  LUNEPACK_E2E_SHELL_APP=$shell_app \
  LUNEPACK_E2E_FAKE_UI=$work/e2e_fake_ui \
  LUNEPACK_E2E_UI=$work/lunepack-ui \
  LUNEPACK_E2E_REQUIRE=1 \
  cargo test --locked -p lunepack-runtime --test e2e
