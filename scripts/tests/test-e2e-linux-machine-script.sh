#!/usr/bin/env bash
# Tests for the guards of scripts/e2e-linux-machine.sh (M11 step 13). Nothing here starts a
# container or a suite: only invalid arguments, --help, the Docker-missing rule (a skip is not a
# pass), the refusals of the inside part off a systemd container, and a scan of what the script
# may remove.
# SC2016: `bash -c '...' _ args` keeps its program in single quotes on purpose.
# shellcheck disable=SC2016
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
SCRIPT=$here/../e2e-linux-machine.sh
ROWS=$here/../e2e-linux-machine-rows.sh
DOCKERFILE=$here/../e2e-linux-machine.Dockerfile
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

run_cmd bash "$SCRIPT" --bogus
t_check "an unknown option is a usage error" rc_is 2
t_check "usage is printed" out_has "usage:"

run_cmd bash "$SCRIPT" extra
t_check "a stray argument is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --build
t_check "--build without a directory is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --build ""
t_check "an empty --build directory is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --inside --build /x
t_check "--inside and --build together are a usage error" rc_is 2

run_cmd bash "$SCRIPT" --inside --inside
t_check "--inside twice is a usage error" rc_is 2

run_cmd bash "$SCRIPT" --help
t_check "--help exits 0" rc_is 0
t_check "--help prints usage" out_has "usage:"

# A skip is not a pass: without Docker the script fails, unless the skip is asked for by name.
run_cmd env LUNEPACK_E2E_DOCKER="$T_TMP/no-such-docker" bash "$SCRIPT"
t_check "without Docker the script exits 1" rc_is 1
t_check "and says Docker is not available" out_has "Docker is not available"
t_check "and says how to skip" out_has "LUNEPACK_E2E_REQUIRE=0"

run_cmd env LUNEPACK_E2E_DOCKER="$T_TMP/no-such-docker" LUNEPACK_E2E_REQUIRE=0 bash "$SCRIPT"
t_check "with LUNEPACK_E2E_REQUIRE=0 a missing Docker is a named skip" rc_is 0
t_check "the skip says SKIP" out_has "SKIP"

# A Docker that answers nothing useful is no Docker.
printf '#!/bin/sh\nexit 1\n' >"$T_TMP/fake-docker"
chmod 755 "$T_TMP/fake-docker"
run_cmd env LUNEPACK_E2E_DOCKER="$T_TMP/fake-docker" bash "$SCRIPT"
t_check "a Docker whose daemon is down exits 1" rc_is 1

# The inside part never runs outside a container with systemd as PID 1, nor as a user.
run_cmd bash "$SCRIPT" --inside
t_check "--inside off a systemd container is refused" rc_is 1
t_check "the refusal says it refuses" out_has "refusing"

# What the script may remove: its own container and its own temporary directory, nothing by
# pattern, nothing pruned.
t_check "no prune anywhere (outside comments)" bash -c '! grep -v "^ *#" "$1" "$2" | grep -nE "prune|rmi -f|rm -rf /|rm -rf \$top|volume rm|network rm"' _ "$SCRIPT" "$ROWS"
t_check "the container is removed by its own name only" bash -c 'grep -c "rm -f \"\$container\"" "$1" | grep -qx 1' _ "$SCRIPT"
t_check "the container name carries this run's pid" grep -qF 'container=lunepack-rs-e2e-machine-$$' "$SCRIPT"
t_check "the image removal is opt-in" bash -c 'grep -q "LUNEPACK_E2E_REMOVE_IMAGES:-0}\" = 1" "$1"' _ "$SCRIPT"
t_check "the image is pinned by digest" bash -c 'grep -qE "^FROM .*@sha256:[0-9a-f]{64}\$" "$1"' _ "$DOCKERFILE"
t_check "the container is started privileged with the host's cgroup namespace" bash -c 'grep -q -- "--privileged --cgroupns=host" "$1"' _ "$SCRIPT"

t_finish
