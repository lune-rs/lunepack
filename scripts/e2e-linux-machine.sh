#!/usr/bin/env bash
# The Linux per-machine end-to-end suite (M11 step 13, M11-D16): an app installed for all users
# under /opt by root and by a standard user through pkexec, then updated, health-checked, rolled
# back, refused, switched and uninstalled by the real runtime, the real update service under
# systemd (socket-activated, `Accept=no`) and the real `lunepack` packager, in a local container
# with systemd as PID 1. It is not part of the gate (scripts/gate.sh) and not part of CI (6750d60:
# machine suites are local).
#
#   scripts/e2e-linux-machine.sh      run the suite (the usual way; needs Docker)
#   scripts/e2e-linux-machine.sh -h   this text
#
# What it does, on this host:
#   1. builds (or finds) the image `lunepack-rs-e2e:<hash>` of scripts/e2e.Dockerfile and, in a
#      throwaway container of it with the worktree read-only, builds the release binaries into a
#      temporary directory: `lunepack`, the static runtime, the static update service (musl) and the
#      shell app of the other end-to-end suite (tests/e2e/shell-app/app.sh);
#   2. builds (or finds) the image `lunepack-rs-e2e-machine:<hash>` of
#      scripts/e2e-linux-machine.Dockerfile (systemd, polkit, pkexec, jq, python3);
#   3. starts ONE container of it, `--privileged --cgroupns=host` with `/sys/fs/cgroup` and a tmpfs
#      `/run`, waits for systemd (`degraded` is accepted: some units of a container fail to start),
#      and runs this script's rows inside, as root and as one standard user;
#   4. removes that container and the temporary directory. The two images are kept (named by the
#      hash of their Dockerfile, like the other suites'; `LUNEPACK_E2E_REMOVE_IMAGES=1` removes the
#      machine image this run used; `LUNEPACK_E2E_KEEP=1` keeps the container and the directory,
#      to look at a failed row by hand). Nothing is pruned; no other container, image, network or
#      volume is touched (the e2e image's two named volumes are the ones scripts/e2e.sh uses).
#
# A skip is not a pass: without Docker the script exits 1, unless LUNEPACK_E2E_REQUIRE=0, which
# prints SKIP and exits 0. The rows are named in the output; a failed check names what differed
# (versions, outcome words, exit codes, file modes), never an environment or a file's text.
#
# Rows (the numbers are the Windows machine suite's, scripts/e2e-windows-machine.ps1):
#   0   static packaging: `pack --service` places the service; the reserved name is refused with and
#       without it; a release without the service installs per user only (34)
#   10  `--all-users --silent` as the standard user: 30, nothing written
#   1   root's `setup --all-users` with a hostile environment: the tree, the record, the units, the
#       socket, the integration; the user cannot write under R; the hostile PATH was never used
#   2   the standard user starts the app and it updates itself through the service, no prompt
#   3   the same through the runtime's command line with --json
#   4   a version that crashes on start (rollback, marked bad, not offered again); one that
#       confirms too slowly (rollback)
#   5   the supervisor killed after the apply: starts inside the lease are not counted, the fourth
#       start past it rolls back in the service
#   6   negatives as the standard user: a flipped byte in the pack, garbage and an oversize frame to
#       the socket, a unit stopped or a write under R (refused)
#   7   the socket's mode tampered to 0600 (refused), a socket the user made at the endpoint
#       (the client refuses before it sends a byte); updates work again when both are gone
#   8   the policy file: disable_self_update (33), no_update_ui, and every broken variant
#   11  the service follows an update; an old tree is kept while the user runs from it and is
#       collected after
#   12  the administrator's uninstall: refused while the user runs the app, nothing changed;
#       complete after (no unit, socket, link, entry, tree or uninstall folder left)
#   9   the standard user installs through pkexec (a polkit rule for that setup path only), updates,
#       and uninstalls through pkexec of the runtime inside R (a rule for that path only)
#   13  a setup file with a flipped byte (verify, nothing under /opt but nothing), and R's parent
#       made group-writable (not_protected)
#
# bash 3.2 compatible (D30) on the host; the inside part runs in the container's bash 5.
set -euo pipefail

self=${BASH_SOURCE[0]}
case $self in
  */*) top=${self%/*}/.. ;;
  *) top=.. ;;
esac
top=$(cd "$top" && pwd)
docker_cmd=${LUNEPACK_E2E_DOCKER:-docker}

usage() {
  echo "usage: scripts/e2e-linux-machine.sh" >&2
}

die() {
  echo "e2e-linux-machine: $*" >&2
  exit 1
}

mode=host
build_out=
while [ "$#" -gt 0 ]; do
  case $1 in
    -h | --help)
      usage
      exit 0
      ;;
    --inside)
      [ "$mode" = host ] || {
        usage
        exit 2
      }
      mode=inside
      shift
      ;;
    --build)
      [ "$mode" = host ] && [ "$#" -ge 2 ] && [ -n "$2" ] || {
        usage
        exit 2
      }
      mode=build
      build_out=$2
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

# ===================================================================================== host ====
if [ "$mode" = host ]; then
  hash_of() { # file
    if command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "$1" | cut -c 1-12
    else
      sha256sum "$1" | cut -c 1-12
    fi
  }

  if ! command -v "$docker_cmd" >/dev/null 2>&1 || ! "$docker_cmd" info >/dev/null 2>&1; then
    if [ "${LUNEPACK_E2E_REQUIRE:-1}" = 0 ]; then
      echo "e2e-linux-machine: SKIP (Docker is not available; LUNEPACK_E2E_REQUIRE=0)"
      exit 0
    fi
    die "Docker is not available (set LUNEPACK_E2E_REQUIRE=0 to skip)"
  fi

  case $("$docker_cmd" version --format '{{.Server.Arch}}' 2>/dev/null) in
    arm64 | aarch64) target=linux-aarch64 ;;
    amd64 | x86_64) target=linux-x86_64 ;;
    *) die "unsupported Docker server architecture" ;;
  esac

  build_image=lunepack-rs-e2e:$(hash_of "$top/scripts/e2e.Dockerfile")
  if ! "$docker_cmd" image inspect "$build_image" >/dev/null 2>&1; then
    echo "e2e-linux-machine: building docker image $build_image from scripts/e2e.Dockerfile"
    "$docker_cmd" build --quiet -t "$build_image" - <"$top/scripts/e2e.Dockerfile" >/dev/null
  fi
  image=lunepack-rs-e2e-machine:$(hash_of "$top/scripts/e2e-linux-machine.Dockerfile")
  if ! "$docker_cmd" image inspect "$image" >/dev/null 2>&1; then
    echo "e2e-linux-machine: building docker image $image from scripts/e2e-linux-machine.Dockerfile"
    "$docker_cmd" build --quiet -t "$image" - <"$top/scripts/e2e-linux-machine.Dockerfile" >/dev/null
  fi

  work=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-e2e-linux-machine.XXXXXX")
  work=$(cd "$work" && pwd -P)
  mkdir "$work/bin"
  container=lunepack-rs-e2e-machine-$$
  # Run by the EXIT trap below.
  # shellcheck disable=SC2329
  cleanup() {
    if [ "${LUNEPACK_E2E_KEEP:-0}" = 1 ]; then
      echo "e2e-linux-machine: kept container $container and $work (remove them by hand)" >&2
      return 0
    fi
    # Only what this run made: its container, its temporary directory and, when asked, its image.
    "$docker_cmd" rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$work"
    if [ "${LUNEPACK_E2E_REMOVE_IMAGES:-0}" = 1 ]; then
      "$docker_cmd" rmi "$image" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup EXIT

  echo "e2e-linux-machine: building the binaries for $target"
  # The binaries are built by the same toolchain image as scripts/e2e.sh, into this run's directory
  # (a bind mount) and the e2e suite's two named volumes. No capability, no new privilege.
  "$docker_cmd" run --rm --init \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$top":/src:ro \
    -v "$work/bin":/out \
    -v lunepack-rs-e2e-target:/target \
    -v lunepack-rs-e2e-cargo:/cargo-home \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_HOME=/cargo-home \
    -e RUSTUP_TOOLCHAIN=1.99.1 \
    -w /src \
    "$build_image" \
    ./scripts/e2e-linux-machine.sh --build /out

  echo "e2e-linux-machine: starting the systemd container"
  "$docker_cmd" run -d --name "$container" \
    --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock \
    -v "$top":/src:ro \
    -v "$work/bin":/e2e/bin:ro \
    "$image" >/dev/null

  state=
  i=0
  while [ "$i" -lt 90 ]; do
    state=$("$docker_cmd" exec "$container" systemctl is-system-running 2>/dev/null || true)
    case $state in
      running | degraded) break ;;
    esac
    i=$((i + 1))
    sleep 1
  done
  case $state in
    running | degraded) ;;
    *) die "systemd did not come up (state: ${state:-none})" ;;
  esac
  echo "e2e-linux-machine: systemd is $state"

  rc=0
  "$docker_cmd" exec -i "$container" /src/scripts/e2e-linux-machine.sh --inside || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "e2e-linux-machine: FAILED (exit $rc)" >&2
    exit "$rc"
  fi
  echo "e2e-linux-machine: ok"
  exit 0
fi

# ==================================================================================== build ====
if [ "$mode" = build ]; then
  [ "$(uname -s)" = Linux ] || die "refusing to run: the build step is Linux only"
  [ -e /.dockerenv ] || [ -e /run/.containerenv ] || die "refusing to run outside a container"
  [ -d "$build_out" ] || die "the output directory is not a directory"
  case $(uname -m) in
    x86_64)
      target=linux-x86_64
      triple=x86_64-unknown-linux-musl
      ;;
    aarch64 | arm64)
      target=linux-aarch64
      triple=aarch64-unknown-linux-musl
      ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
  tdir=${CARGO_TARGET_DIR:-$top/target}
  cd "$top"
  ./scripts/build-runtime.sh "$target" --out "$build_out/lunepack-runtime"
  # The update service is a static executable too: `pack --service` holds it to the runtime's checks.
  cargo build --locked --release -p lunepack-service --target "$triple" --config profile.release.strip=true
  cp "$tdir/$triple/release/lunepack-service" "$build_out/lunepack-service"
  cargo build --locked --release -p lunepack-cli
  cp "$tdir/release/lunepack" "$build_out/lunepack"
  cp "$top/crates/lunepack-runtime/tests/e2e/shell-app/app.sh" "$build_out/app.sh"
  chmod 755 "$build_out/lunepack-runtime" "$build_out/lunepack-service" "$build_out/lunepack" "$build_out/app.sh"
  echo "e2e-linux-machine: built $target"
  exit 0
fi

# =================================================================================== inside ====
[ "$(uname -s)" = Linux ] || die "refusing to run: the rows are Linux only (run scripts/e2e-linux-machine.sh)"
[ -e /.dockerenv ] || [ -e /run/.containerenv ] || die "refusing to run outside a container"
[ "$(id -u)" = 0 ] || die "refusing to run: the rows start as root"
[ "$(cat /proc/1/comm 2>/dev/null || true)" = systemd ] || die "refusing to run: PID 1 is not systemd"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=e2e-linux-machine-rows.sh
. "$top/scripts/e2e-linux-machine-rows.sh"
run_rows
