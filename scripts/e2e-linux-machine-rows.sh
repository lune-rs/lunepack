#!/usr/bin/env bash
# The rows of scripts/e2e-linux-machine.sh (sourced by it inside the systemd container, as root).
# See that script's header for the list. Nothing here runs on the host.
#
# One app, `org.lunepack.e2e` (display name `Lunepack E2E`, command link `lunepack-e2e`): the shell
# app of the other end-to-end suite (tests/e2e/shell-app/app.sh) as entry `bin/e2e-app`, packed with
# the real runtime and the real update service, versions 1.0.0 and up in one `file:` feed under a
# folder the standard user may read. Every command of the standard user runs as `lpuser` with an
# empty environment but HOME and PATH (and the outcome file's name). Outcomes go to a file the app
# writes (`<tree version> <outcome>` lines, see the app).
# shellcheck shell=bash
# SC2016: `bash -c '...' _ args` keeps its program in single quotes on purpose (the arguments are
# the values). SC2012 and SC2010: names listed here are plain ASCII names of this suite's own.
# shellcheck disable=SC2016,SC2012,SC2010

APP=org.lunepack.e2e
NAME='Lunepack E2E'
BIN=lunepack-e2e
R=/opt/$APP
SOCK=/run/lunepack/$APP.sock
UNIT_DIR=/etc/systemd/system
POLICY_FILE=/etc/lunepack/policy/$APP.json
RULES=/etc/polkit-1/rules.d/49-lunepack-e2e.rules
W=/srv/lpe
PUB=$W/pub
RD=$W/release
SETUPS=$W/setup
UNAME=lpuser
UH=/home/lpuser
UOUT=$UH/outcome.txt
CLI=/e2e/bin/lunepack
RT=/e2e/bin/lunepack-runtime
SVC=/e2e/bin/lunepack-service
APPSH=/e2e/bin/app.sh
FAILURES=0
CHECKS=0
ROW=

case $(uname -m) in
  x86_64) TARGET=linux-x86_64 ;;
  *) TARGET=linux-aarch64 ;;
esac

# ---- reporting -------------------------------------------------------------------------------

row() {
  ROW=$1
  echo "== row $1"
}

fail() {
  FAILURES=$((FAILURES + 1))
  echo "  FAIL [$ROW]: $1" >&2
}

# check LABEL COMMAND...: passes when the command succeeds.
check() {
  local label=$1
  shift
  CHECKS=$((CHECKS + 1))
  if "$@"; then
    echo "  ok: $label"
  else
    fail "$label"
  fi
}

# eq LABEL ACTUAL EXPECTED: shows both on a difference (values here are words, versions and codes).
eq() {
  CHECKS=$((CHECKS + 1))
  if [ "$2" = "$3" ]; then
    echo "  ok: $1"
  else
    fail "$1 (got '$2', want '$3')"
  fi
}

# ---- running things --------------------------------------------------------------------------

# as_user COMMAND...: as the standard user, with an empty environment but HOME, PATH and the
# outcome file's name. A command that does not exist is a failure of the row, not of the script.
as_user() {
  runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" "$@"
}

# The exit code of a command. Its stdout and stderr are kept in $LAST_OUT and $LAST_ERR (files, so
# they survive a command substitution); nothing is printed unless a row asks.
LAST_OUT=/tmp/lpe-last.out
LAST_ERR=/tmp/lpe-last.err
OUT=
run() { # COMMAND...
  local rc=0
  "$@" >"$LAST_OUT" 2>"$LAST_ERR" </dev/null || rc=$?
  OUT=$(cat "$LAST_OUT")
  return "$rc"
}

# rc_of COMMAND...: the exit code, whatever it is.
rc_of() {
  local rc=0
  run "$@" || rc=$?
  echo "$rc"
}

wait_for() { # SECONDS COMMAND...: true as soon as the command succeeds
  local limit=$1 n=0
  shift
  while [ "$n" -lt $((limit * 5)) ]; do
    if "$@"; then
      return 0
    fi
    sleep 0.2
    n=$((n + 1))
  done
  return 1
}

# The last line of a command's stdout as JSON member `$1`.
last_member() { # MEMBER
  grep -v '^$' "$LAST_OUT" | tail -n 1 | jq -r ".$1 // empty" 2>/dev/null || true
}

# ---- publishing ------------------------------------------------------------------------------

cli() { # the lunepack command line, in the publisher's directory, with nothing of the environment
  (cd "$PUB" && env -i HOME="$PUB/home" PATH=/usr/bin:/bin "$CLI" "$@")
}

write_config() { # VERSION HEALTH_TIMEOUT
  cat >"$PUB/release-$1.toml" <<EOF
app_id = "$APP"

[root]
version = 1
threshold = 1
keys = ["$ROOT_PUB"]

[signers.root]
file = "root.key"

[signers.release]
file = "release.key"

[update]
feed = "file://$RD/"
channel = "stable"
health_timeout_secs = $2

[install]
entry = "bin/e2e-app"
name = "$NAME"
comment = "The lunepack machine end-to-end app"
categories = ["Utility"]
bin = "$BIN"
terminal = false
EOF
}

# publish VERSION HEALTH_TIMEOUT [FLAG...]: packs the shell app with the runtime and the service,
# adds the release to the feed. The flags are lines of the app's `e2e-flags` marker.
publish() {
  local v=$1 timeout=$2 flag input
  shift 2
  input=$W/in-$v
  rm -rf "$input"
  mkdir -p "$input/bin" "$input/share"
  install -m 0755 "$APPSH" "$input/bin/e2e-app"
  printf '%s\n' "$v" >"$input/share/version.txt"
  for flag in "$@"; do
    printf '%s\n' "$flag" >>"$input/e2e-flags"
  done
  write_config "$v" "$timeout"
  cli pack --input "$input" --version "$v" --target "$TARGET" --release-dir "$RD" \
    --sign release --runtime "$RT" --service "$SVC" --config "$PUB/release-$v.toml" >/dev/null
  cli feed add --release-dir "$RD" --channel stable --version "$v" --sign release \
    --config "$PUB/lunepack.toml" >/dev/null
  chmod -R a+rX "$RD"
}

# setup_of VERSION: builds the Linux setup file of a published version (readable by everyone).
setup_of() {
  local out=$SETUPS/$APP-$1-$TARGET-setup
  if [ -e "$out" ]; then
    echo "$out"
    return 0
  fi
  cli setup "$RD" --version "$1" --target "$TARGET" --out "$out" --config "$PUB/lunepack.toml" >/dev/null
  chmod 755 "$out"
  echo "$out"
}

setup_publisher() {
  rm -rf "$W"
  install -d -m 755 "$W" "$RD" "$SETUPS"
  install -d -m 700 "$PUB" "$PUB/home"
  local out root_pub release_pub
  out=$(cli keys gen "$PUB/root.key")
  root_pub=$(printf '%s\n' "$out" | sed -n 's/^public: //p')
  out=$(cli keys gen "$PUB/release.key")
  release_pub=$(printf '%s\n' "$out" | sed -n 's/^public: //p')
  ROOT_PUB=$root_pub
  cli init --app-id "$APP" --root-key "$root_pub" --config "$PUB/lunepack.toml" >/dev/null
  # `init` wrote the config; the full one replaces it (the publisher's state file stays).
  write_config 1.0.0 60
  cp "$PUB/release-1.0.0.toml" "$PUB/lunepack.toml"
  cli keys set --release-dir "$RD" --release-key "$release_pub" --sign root \
    --config "$PUB/lunepack.toml" >/dev/null
  chmod -R a+rX "$RD"
}

# ---- what is installed -----------------------------------------------------------------------

# The version `R/current` names (empty when there is no link).
current() {
  local t
  t=$(readlink "$R/current" 2>/dev/null) || return 0
  printf '%s\n' "${t#app/}"
}

# The trees under R/app, sorted, as one line.
trees() {
  { ls "$R/app" 2>/dev/null || true; } | tr '\n' ' ' | sed 's/ $//'
}

# One line per file under the places a machine install writes, with kind, mode and owner. The
# rows that must change nothing compare two of them. Content is not read.
footprint() {
  {
    # The record's files and the service's log are the service's own bookkeeping (a record file is
    # replaced by the next number at every commit): the rows judge them through the trees and the
    # version `R/current` names.
    find "$R" /usr/local /etc/xdg /run/lunepack /etc/lunepack -xdev ! -path '*/.lunepack/state/*' ! -path '*/.lunepack/logs/*' -printf '%p %y %m %U:%G %l\n' 2>/dev/null || true
    ls -1 "$UNIT_DIR" | grep '^lunepack-' || true
    ls -1 /opt
  } | sort
}

installed() { [ -e "$R/.lunepack/state" ]; }

# Nothing of a machine install (of this app) is left anywhere a machine install writes.
nothing_left() {
  local left=0 p
  for p in "$R" "$SOCK" "$UNIT_DIR/lunepack-$APP.socket" "$UNIT_DIR/lunepack-$APP.service" \
    "/usr/local/bin/$BIN" "/usr/local/share/applications/$APP.desktop" \
    "/etc/xdg/autostart/$APP.desktop"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      echo "  left over: $p" >&2
      left=1
    fi
  done
  if ls -d /opt/.lunepack-* >/dev/null 2>&1; then
    echo "  left over: /opt/.lunepack-*" >&2
    left=1
  fi
  if systemctl list-unit-files "lunepack-$APP.*" --no-legend 2>/dev/null | grep -q lunepack; then
    echo "  left over: a unit file is still registered" >&2
    left=1
  fi
  [ "$left" -eq 0 ]
}

# ---- the standard user's app -----------------------------------------------------------------

outcomes() { cat "$UOUT" 2>/dev/null || true; }
has_outcome() { outcomes | grep -qxF "$1"; }
reset_outcomes() { : >"$UOUT"; chown "$UNAME" "$UOUT"; }

# The standard user starts the installed app, detached from this shell, with the given arguments.
app_start() {
  runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" \
    "$R/current/bin/e2e-app" "$@" >/dev/null 2>&1 </dev/null
}

# The service's running state as `systemctl` says (never fatal).
service_active() { systemctl is-active --quiet "lunepack-$APP.service"; }
socket_active() { systemctl is-active --quiet "lunepack-$APP.socket"; }

# ---- the polkit rule of the pkexec row ---------------------------------------------------------

allow_pkexec() { # PROGRAM
  cat >"$RULES" <<EOF
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.policykit.exec" && subject.user == "$UNAME" &&
      action.lookup("program") == "$1") {
    return polkit.Result.YES;
  }
});
EOF
  chmod 644 "$RULES"
  sleep 1
}

forbid_pkexec() { rm -f "$RULES"; sleep 1; }

# =============================================================================== the rows ======

row_static_packaging() {
  row "0 static packaging"
  local input=$W/in-static tree
  rm -rf "$input"
  mkdir -p "$input/bin"
  install -m 0755 "$APPSH" "$input/bin/e2e-app"
  write_config 0.9.0 60
  cli pack --input "$input" --version 0.9.0 --target "$TARGET" --release-dir "$RD" --sign release \
    --runtime "$RT" --service "$SVC" --config "$PUB/release-0.9.0.toml" >/dev/null
  # What the packer placed: the service beside the entry, executable, byte for byte.
  local out=$W/unpack-0.9.0
  rm -rf "$out"
  check "the setup file of a release with the service builds" \
    cli feed add --release-dir "$RD" --channel stable --version 0.9.0 --sign release --config "$PUB/lunepack.toml"
  local setup
  setup=$(setup_of 0.9.0)
  check "the setup file is an executable" test -x "$setup"
  tree=$(grep -a -c 'lunepack-service' "$setup" || true)
  check "the service is in the setup file" test "${tree:-0}" -gt 0
  # The reserved name, with and without --service.
  mkdir -p "$W/in-reserved/bin"
  install -m 0755 "$APPSH" "$W/in-reserved/bin/e2e-app"
  install -m 0755 "$SVC" "$W/in-reserved/bin/lunepack-service"
  local rc
  rc=$(rc_of cli pack --input "$W/in-reserved" --version 0.9.1 --target "$TARGET" --release-dir "$RD" --sign release --runtime "$RT" --service "$SVC" --config "$PUB/release-0.9.0.toml")
  check "the service's name is reserved with --service (exit $rc)" test "$rc" -ne 0
  rc=$(rc_of cli pack --input "$W/in-reserved" --version 0.9.1 --target "$TARGET" --release-dir "$RD" --sign release --runtime "$RT" --config "$PUB/release-0.9.0.toml")
  check "the service's name is reserved without --service (exit $rc)" test "$rc" -ne 0
  # Nothing of it reached the machine.
  check "packaging wrote nothing under /opt" test -z "$(ls -A /opt)"
  rm -rf "$W/in-reserved" "$W/in-static"
}

row_user_all_users_silent() {
  row "10 --all-users --silent as the standard user"
  local setup before after rc
  setup=$(setup_of 1.0.0)
  before=$(footprint)
  rc=$(rc_of as_user "$setup" --all-users --silent)
  eq "elevation_required (30)" "$rc" 30
  check "the result names it" grep -q elevation_required "$LAST_OUT"
  after=$(footprint)
  eq "nothing was written" "$after" "$before"
  check "nothing left" nothing_left
}

row_no_service_release() {
  row "0b a release without the service installs per user only"
  # A release packed without the service: root's --all-users says so (34) and writes nothing.
  local input=$W/in-plain rc setup before
  rm -rf "$input"
  mkdir -p "$input/bin"
  install -m 0755 "$APPSH" "$input/bin/e2e-app"
  write_config 0.8.0 60
  cli pack --input "$input" --version 0.8.0 --target "$TARGET" --release-dir "$RD" --sign release \
    --runtime "$RT" --config "$PUB/release-0.8.0.toml" >/dev/null
  cli feed add --release-dir "$RD" --channel stable --version 0.8.0 --sign release \
    --config "$PUB/lunepack.toml" >/dev/null
  chmod -R a+rX "$RD"
  setup=$(setup_of 0.8.0)
  before=$(footprint)
  rc=$(rc_of "$setup" --all-users)
  eq "per_machine_unavailable (34)" "$rc" 34
  eq "nothing was written" "$(footprint)" "$before"
  rm -rf "$input"
}

row_root_install() {
  row "1 root's --all-users with a hostile environment"
  local setup hostile=/tmp/hostile rc before
  setup=$(setup_of 1.0.0)
  rm -rf "$hostile"
  mkdir -p "$hostile/bin" "$hostile/tmp" "$hostile/home" "$hostile/xdg"
  # Any program the root side ran by name through PATH would leave this mark.
  for tool in systemctl systemd-run sh env; do
    printf '#!/bin/sh\ntouch %s/ran-%s\nexit 0\n' "$hostile" "$tool" >"$hostile/bin/$tool"
    chmod 755 "$hostile/bin/$tool"
  done
  before=$(ls -A "$hostile" | tr '\n' ' ')
  rc=$(rc_of env -i HOME="$hostile/home" XDG_DATA_HOME="$hostile/xdg" XDG_CONFIG_HOME="$hostile/xdg" \
    XDG_CACHE_HOME="$hostile/xdg" TMPDIR="$hostile/tmp" PATH="$hostile/bin" DISPLAY=:99 \
    LUNEPACK_NO_UI=0 "$setup" --all-users --silent)
  eq "installed (0)" "$rc" 0
  eq "the result" "$(last_member outcome)" installed
  eq "the hostile directory was never used" "$(ls -A "$hostile" | tr '\n' ' ')" "$before"
  check "no hostile program ran" bash -c '! ls "$1"/ran-* >/dev/null 2>&1' _ "$hostile"
  rm -rf "$hostile"

  eq "R/current names the installed version" "$(current)" 1.0.0
  eq "the tree" "$(trees)" 1.0.0
  check "the entry is there" test -x "$R/app/1.0.0/bin/e2e-app"
  check "the runtime is beside it" test -x "$R/app/1.0.0/bin/lunepack-runtime"
  check "the service is in the tree" test -x "$R/app/1.0.0/bin/lunepack-service"
  eq "R is root's, not writable by others" "$(stat -c '%u:%g %a' "$R")" "0:0 755"
  eq "the machine folder is root's alone" "$(stat -c '%u:%g %a' "$R/.lunepack/machine")" "0:0 700"
  eq "the record is readable" "$(stat -c '%a' "$R/.lunepack/state")" 755
  check "the service image is linked and executable" test -x "$R/.lunepack/machine/lunepack-service"
  check "the service unit is registered" test -f "$UNIT_DIR/lunepack-$APP.service"
  check "the socket unit is registered" test -f "$UNIT_DIR/lunepack-$APP.socket"
  check "the socket is listening" socket_active
  eq "the socket's mode and owner" "$(stat -c '%a %U' "$SOCK")" "666 root"
  eq "the socket's directory" "$(stat -c '%a %U' /run/lunepack)" "755 root"
  check "the command link points into R/current" bash -c '[ "$(readlink "$1")" = "$2/current/bin/e2e-app" ]' _ "/usr/local/bin/$BIN" "$R"
  check "the desktop entry is there and validates" bash -c 'desktop-file-validate "$1"' _ "/usr/local/share/applications/$APP.desktop"
  check "no autostart entry (the app has none)" test ! -e "/etc/xdg/autostart/$APP.desktop"
  check "the staging folder is gone" bash -c '! ls -d /opt/.lunepack-* >/dev/null 2>&1'
  # The standard user may read and run, and write nothing there.
  check "the user can run the app" as_user "$R/current/bin/e2e-app"
  check "the user cannot write under R" bash -c '! runuser -u "$1" -- touch "$2/x" 2>/dev/null' _ "$UNAME" "$R"
  check "the user cannot write in the tree" bash -c '! runuser -u "$1" -- touch "$2/app/1.0.0/x" 2>/dev/null' _ "$UNAME" "$R"
  check "the user cannot touch the machine folder" bash -c '! runuser -u "$1" -- ls "$2/.lunepack/machine" >/dev/null 2>&1' _ "$UNAME" "$R"
  has_outcome "1.0.0 confirmed" || has_outcome "1.0.0 nothing-pending" || fail "the app did not run"
  # A second install of the same app: refused, nothing changed.
  local snap
  snap=$(footprint)
  rc=$(rc_of "$setup" --all-users --silent)
  eq "a second install is already_installed (23)" "$rc" 23
  eq "and changes nothing" "$(footprint)" "$snap"
}

# The user's update through the app (row 2) and through the runtime's command line (row 3).
row_user_update_through_the_app() {
  row "2 the standard user updates the app through the service"
  publish 1.1.0 60
  reset_outcomes
  app_start --update --no-ui || true
  check "the app scheduled the update" wait_for 30 has_outcome "1.0.0 apply-scheduled"
  check "the new version confirmed through the service" wait_for 60 has_outcome "1.1.0 confirmed"
  eq "R/current follows the confirm" "$(current)" 1.1.0
  check "the new tree is readable and executable by the user" as_user test -x "$R/app/1.1.0/bin/e2e-app"
  check "the service image follows the confirm" bash -c '[ "$(readlink "$1")" = "service/1.1.0/lunepack-service" ] || readlink "$1" | grep -q 1.1.0' _ "$R/.lunepack/machine/lunepack-service"
  check "the update marked the arguments" has_outcome "1.1.0 arg after-update"
  check "an updated event reached the app" has_outcome "1.1.0 event updated 1.0.0"
  check "no prompt was needed: no pkexec ran" bash -c '! pgrep -x pkexec >/dev/null'
  check "the user's home holds only the user's own files" bash -c '[ -z "$(find "$1" -xdev ! -user "$2" 2>/dev/null)" ]' _ "$UH" "$UNAME"
}

row_user_update_through_the_cli() {
  row "3 the same through the runtime's command line"
  publish 1.2.0 60
  local rt=$R/current/bin/lunepack-runtime
  run as_user "$rt" check --json
  eq "check finds 1.2.0" "$(last_member update.version)" 1.2.0
  run as_user "$rt" download --json --expect-version 1.2.0
  eq "download stages it" "$(last_member staged)" true
  check "the staged tree is under R/app" test -d "$R/app/1.2.0"
  eq "and the record has not moved" "$(current)" 1.1.0
  reset_outcomes
  (runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" \
    sh -c "sleep 2 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.2.0 --no-ui -- --after-update" \
    >"$W/apply.json" 2>&1 </dev/null) || true
  check "the new app ran and confirmed" wait_for 60 has_outcome "1.2.0 confirmed"
  eq "R/current follows" "$(current)" 1.2.0
  check "the result named the version" bash -c 'tail -n 1 "$1" | jq -e ".version == \"1.2.0\"" >/dev/null || tail -n 1 "$1" | grep -q 1.2.0' _ "$W/apply.json"
}

row_crash_rollback() {
  row "4 a crashing version and a slow one are rolled back"
  local rt=$R/current/bin/lunepack-runtime
  publish 1.3.0 20 crash-on-start
  run as_user "$rt" download --json --expect-version 1.3.0
  reset_outcomes
  (runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" \
    sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.3.0 --no-ui" \
    >/dev/null 2>&1 </dev/null) || true
  check "the bad version crashed on start" wait_for 60 has_outcome "1.3.0 crash"
  check "and the old one came back" wait_for 60 has_outcome "1.2.0 start"
  eq "R/current is back" "$(current)" 1.2.0
  run as_user "$rt" check --json
  eq "the bad version is not offered again" "$(last_member update)" ""

  publish 1.4.0 5 'slow-confirm 30'
  run as_user "$rt" download --json --expect-version 1.4.0
  reset_outcomes
  (runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" \
    sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.4.0 --no-ui" \
    >/dev/null 2>&1 </dev/null) || true
  check "the slow version started" wait_for 60 has_outcome "1.4.0 slow-confirm"
  check "and was rolled back before it confirmed" wait_for 90 bash -c "[ \"\$(readlink $R/current)\" = app/1.2.0 ]"
  check "the old one is running again" wait_for 60 has_outcome "1.2.0 start"
  check "the slow one never confirmed" bash -c '! grep -qx "1.4.0 confirmed" "$1"' _ "$UOUT"
}

row_supervisor_killed() {
  row "5 the supervisor killed after the apply"
  local rt=$R/current/bin/lunepack-runtime i
  # The new version lives (it waits before it confirms), so the supervisor does not roll it back.
  publish 1.5.0 10 'slow-confirm 120'
  run as_user "$rt" download --json --expect-version 1.5.0
  reset_outcomes
  (runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" \
    sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.5.0 --no-ui" \
    >/dev/null 2>&1 </dev/null) || true
  check "the new version was committed" wait_for 30 bash -c "[ \"\$(readlink $R/current)\" = app/1.5.0 ]"
  check "and started" wait_for 30 has_outcome "1.5.0 slow-confirm"
  # The supervisor (the user's `apply` runtime) and the version it started die: nobody holds the
  # token, nobody watches. The version stays pending in the service's record.
  pkill -9 -u "$UNAME" -f 'lunepack-runtime apply' || true
  pkill -9 -u "$UNAME" -f 'e2e-app' || true
  sleep 1
  eq "the version is still the pending one" "$(current)" 1.5.0
  # A start inside the lease asks `attempt` but is not counted. A start lives 4 seconds here: its
  # `startup` is what counts, it would otherwise wait for its slow confirm.
  try_start() { timeout 4 runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" "$R/current/bin/e2e-app" >/dev/null 2>&1 </dev/null || true; }
  try_start
  try_start
  eq "starts inside the lease roll nothing back" "$(current)" 1.5.0
  # Past the lease (the health timeout and its grace, 25 s) a start counts and starts a lease of
  # its own: three starts, each past the last one's lease, are counted; the fourth rolls back.
  for i in 1 2 3; do
    sleep 26
    try_start
    eq "counted start $i keeps the pending version" "$(current)" 1.5.0
  done
  sleep 26
  try_start
  check "the fourth start past a lease rolls back in the service" wait_for 20 bash -c "[ \"\$(readlink $R/current)\" = app/1.2.0 ]"
  run as_user "$rt" check --json
  eq "the version marked bad is not offered again" "$(last_member update)" ""
}

# A raw client of the socket (python): sends bytes, prints what came back as hex length and whether
# the peer closed.
sock_client() { # PATH HEX-OF-BYTES-TO-SEND
  as_user python3 - "$1" "$2" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sys.argv[1])
    s.sendall(bytes.fromhex(sys.argv[2]))
    s.shutdown(socket.SHUT_WR)
    n = 0
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            n += len(d)
    except OSError:
        pass
    print("connected received=%d" % n)
except OSError as e:
    print("error %s" % e.errno)
PY
}

row_negatives() {
  row "6 negatives as the standard user"
  local rt=$R/current/bin/lunepack-runtime snap v=1.6.0 file
  publish $v 60
  # Flipped bytes in the pack the user would fetch (one in every 97: whichever frames it fetches
  # are hit): the library refuses it (verify) and stages nothing.
  file=$(find "$RD" -path "*1.6.0*" -name '*.pack' | head -n 1)
  cp "$file" "$W/pack.bak"
  python3 - "$file" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
for i in range(100, len(b), 97):
    b[i] ^= 1
open(p, 'wb').write(b)
PY
  snap=$(footprint)
  eq "flipped bytes in the pack are verify (7)" "$(rc_of as_user "$rt" download --json --expect-version $v)" 7
  eq "nothing was staged" "$(trees | grep -c "$v" || true)" 0
  eq "nothing changed under R" "$(footprint)" "$snap"
  cp "$W/pack.bak" "$file"
  chmod a+r "$file"
  # Garbage and an oversize frame to the socket: the service answers or closes, and goes on.
  snap=$(footprint)
  run sock_client "$SOCK" "$(python3 -c 'print(b"this is not a frame\n".hex())')"
  check "garbage: the connection ended without a crash ($OUT)" grep -q '^connected' "$LAST_OUT"
  run sock_client "$SOCK" "$(python3 -c 'print((b"\xff\xff\xff\xff" + b"a" * 64).hex())')"
  check "an oversize frame: the connection ended ($OUT)" grep -q '^connected' "$LAST_OUT"
  check "the socket is still listening" socket_active
  eq "nothing changed" "$(footprint)" "$snap"
  eq "updates still work" "$(rc_of as_user "$rt" download --json --expect-version $v)" 0
  # Not the user's to change: the units, R.
  check "the user cannot stop the socket" bash -c '! runuser -u "$1" -- systemctl stop "lunepack-$2.socket" >/dev/null 2>&1' _ "$UNAME" "$APP"
  check "the user cannot edit a unit" bash -c '! runuser -u "$1" -- sh -c "echo x >> $2/lunepack-$3.service" 2>/dev/null' _ "$UNAME" "$UNIT_DIR" "$APP"
  check "the socket is still listening" socket_active
}

row_socket() {
  row "7 a socket that is not the service's"
  local rt=$R/current/bin/lunepack-runtime
  # The mode tampered to 0600: the user cannot even connect.
  chmod 600 "$SOCK"
  local rc
  rc=$(rc_of as_user "$rt" download --json --expect-version 1.6.0)
  check "a socket of mode 0600 is refused (exit $rc)" test "$rc" -ne 0
  eq "its error is the service being unavailable" "$(last_member kind)" service_unavailable
  chmod 666 "$SOCK"
  eq "updates work again" "$(rc_of as_user "$rt" download --json --expect-version 1.6.0)" 0
  # A socket owned by the user at the endpoint: the client refuses before it sends a byte.
  systemctl stop "lunepack-$APP.socket" "lunepack-$APP.service" 2>/dev/null || true
  rm -f "$SOCK"
  python3 - "$SOCK" "$UNAME" "$W/fake-got" <<'PY' &
import os, pwd, socket, sys, time
path, user, log = sys.argv[1:4]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
os.chown(path, pwd.getpwnam(user).pw_uid, -1)
os.chmod(path, 0o666)
s.listen(4)
s.settimeout(30)
total = 0
try:
    while True:
        c, _ = s.accept()
        c.settimeout(2)
        try:
            total += len(c.recv(4096))
        except OSError:
            pass
        c.close()
except OSError:
    pass
open(log, "w").write(str(total))
PY
  local fake=$!
  wait_for 10 test -S "$SOCK"
  rc=$(rc_of as_user "$rt" download --json --expect-version 1.6.0)
  check "a fake socket owned by the user is refused (exit $rc)" test "$rc" -ne 0
  eq "the error is the service being unavailable" "$(last_member kind)" service_unavailable
  kill "$fake" 2>/dev/null || true
  wait "$fake" 2>/dev/null || true
  eq "the fake service received nothing" "$(cat "$W/fake-got" 2>/dev/null || echo 0)" 0
  rm -f "$SOCK" "$W/fake-got"
  systemctl start "lunepack-$APP.socket"
  wait_for 10 test -S "$SOCK"
  eq "updates work again with the real socket" "$(rc_of as_user "$rt" download --json --expect-version 1.6.0)" 0
}

row_policy() {
  row "8 the administrator's policy file"
  local rt=$R/current/bin/lunepack-runtime
  mkdir -p "$(dirname "$POLICY_FILE")"
  chmod 755 /etc/lunepack /etc/lunepack/policy
  publish 1.7.0 60
  policy() { # BODY [CHOWN]
    printf '%s' "$1" >"$POLICY_FILE"
    chmod 644 "$POLICY_FILE"
    chown "${2:-root:root}" "$POLICY_FILE"
  }
  # disable_self_update: the service refuses to stage; the command says 33.
  policy '{"disable_self_update":true}'
  eq "disable_self_update is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
  eq "the version was not staged" "$(trees | grep -c 1.7.0 || true)" 0
  # Every broken variant fails toward no update (33).
  local body
  for body in '{"disable_self_update":false,"disable_self_update":false}' '{"unknown":true}' \
    '{"no_update_ui":"yes"}' 'not json' '[]' ''; do
    policy "$body"
    eq "a broken policy ($body) is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
  done
  policy "$(python3 -c 'print("{\"no_update_ui\":true}" + " " * 5000)')"
  eq "a policy over 4 KiB is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
  policy '{"no_update_ui":false}' "$UNAME:$UNAME"
  eq "a policy owned by the user is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
  policy '{"no_update_ui":false}'
  chmod 664 "$POLICY_FILE"
  eq "a group-writable policy is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
  chmod 755 /etc/lunepack
  chmod 777 /etc/lunepack/policy
  policy '{"no_update_ui":false}'
  eq "a policy in a world-writable directory is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
  chmod 755 /etc/lunepack/policy
  # no_update_ui alone changes nothing of the update itself.
  policy '{"no_update_ui":true}'
  eq "no_update_ui alone: the download works" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 0
  # No file at all: both off.
  rm -f "$POLICY_FILE"
  eq "no policy file: the download works" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 0
  rmdir /etc/lunepack/policy /etc/lunepack 2>/dev/null || true
}

row_service_switch() {
  row "11 a service switch; an old tree kept while the user runs from it"
  local rt=$R/current/bin/lunepack-runtime old holder
  old=$(current)
  # The user keeps a process in the current tree (its working directory); two updates follow.
  runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin sh -c "cd $R/app/$old/bin && exec sleep 300" </dev/null >/dev/null 2>&1 &
  holder=$!
  sleep 1
  # Called through `check`.
  # shellcheck disable=SC2329
  update_to() { # VERSION
    publish "$1" 60
    run as_user "$R/current/bin/lunepack-runtime" download --json --expect-version "$1"
    reset_outcomes
    (runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$UOUT" \
      sh -c "sleep 1 & exec \"$R/current/bin/lunepack-runtime\" apply-and-restart --json --wait-pid \$! --expect-version $1 --no-ui -- --after-update" \
      >/dev/null 2>&1 </dev/null) || true
    wait_for 60 has_outcome "$1 confirmed"
  }
  check "1.8.0 confirmed" update_to 1.8.0
  check "1.9.0 confirmed" update_to 1.9.0
  eq "R/current" "$(current)" 1.9.0
  check "the service image follows the switch" bash -c 'readlink "$1" | grep -q 1.9.0' _ "$R/.lunepack/machine/lunepack-service"
  check "the tree the user runs from is kept ($old)" test -d "$R/app/$old"
  kill "$holder" 2>/dev/null || true
  wait "$holder" 2>/dev/null || true
  check "1.9.1 confirmed" update_to 1.9.1
  check "the old tree is collected once nobody runs from it" wait_for 30 bash -c "[ ! -e $R/app/$old ]"
  check "the previous tree is kept for a rollback" test -d "$R/app/1.9.0"
}

row_uninstall() {
  row "12 the administrator's uninstall"
  local rt=$R/current/bin/lunepack-runtime snap
  # The user runs a program from the current tree while root asks to uninstall: refused, unchanged.
  runuser -u "$UNAME" -- env -i HOME="$UH" PATH=/usr/bin:/bin sh -c "cd $R/current/bin && exec sleep 40" </dev/null >/dev/null 2>&1 &
  local keeper=$!
  sleep 1
  # Running as the user from inside R: a process whose working directory is in R.
  snap=$(footprint)
  local rc
  rc=$(rc_of "$rt" uninstall)
  eq "refused while the user runs from R (in_use, 25)" "$rc" 25
  eq "the error is named" "$(last_member kind)" in_use
  eq "nothing changed" "$(footprint)" "$snap"
  check "no uninstall folder is left" bash -c '! ls -d /opt/.lunepack-uninstall-* >/dev/null 2>&1'
  check "the app still starts" as_user "$R/current/bin/e2e-app"
  kill "$keeper" 2>/dev/null || true
  wait "$keeper" 2>/dev/null || true
  sleep 1
  rc=$(rc_of "$rt" uninstall)
  eq "complete when nothing runs from R (0)" "$rc" 0
  eq "the result" "$(last_member outcome)" uninstalled
  check "nothing of the install is left" nothing_left
  check "no process of ours is left" bash -c '! pgrep -f "lunepack-(runtime|service)" >/dev/null'
  eq "the user's own files are the user's" "$(stat -c %U "$UH")" "$UNAME"
}

row_pkexec() {
  row "9 the standard user installs and uninstalls through pkexec"
  local setup rc rt
  setup=$(setup_of 1.0.0)
  # No rule: pkexec has no agent here and the user is shown the command to run (30).
  forbid_pkexec
  rc=$(rc_of as_user "$setup" --all-users)
  eq "without a polkit rule: elevation_required (30)" "$rc" 30
  check "nothing was installed" nothing_left
  allow_pkexec "$setup"
  rc=$(rc_of as_user "$setup" --all-users)
  eq "through pkexec: installed (0)" "$rc" 0
  eq "the result" "$(last_member outcome)" installed
  eq "R/current" "$(current)" 1.0.0
  check "the unit and the socket are registered" socket_active
  check "the root child's progress crossed pkexec's stdout (a copy that reached its end)" \
    bash -c 'jq -e "select(.type==\"progress\" and .done > 0 and .done == .total)" "$1" >/dev/null' _ "$LAST_ERR"
  forbid_pkexec
  check "no staging folder" bash -c '! ls -d /opt/.lunepack-* >/dev/null 2>&1'
  # An update by the user, as in row 2.
  publish 1.10.0 60
  reset_outcomes
  app_start --update --no-ui || true
  check "the user's update confirmed" wait_for 60 has_outcome "1.10.0 confirmed"
  # The unelevated uninstall: a copy of the runtime in the user's home, then pkexec of the runtime
  # inside R (a rule for that path only).
  rt=$R/app/1.10.0/bin/lunepack-runtime
  rc=$(rc_of as_user "$rt" uninstall --silent)
  eq "--silent as the user: elevation_required (30)" "$rc" 30
  check "nothing was removed" installed
  rc=$(rc_of as_user "$rt" uninstall)
  eq "without a rule: elevation_required (30)" "$rc" 30
  check "still installed" installed
  allow_pkexec "$rt"
  rc=$(rc_of as_user "$rt" uninstall)
  eq "through pkexec: uninstalled (0)" "$rc" 0
  forbid_pkexec
  check "nothing of the install is left" nothing_left
  check "the user's copy folder is gone with the user's home for the app" bash -c '! ls -d "$1"/.local/share/.lunepack/*/lunepack-uninstall-* >/dev/null 2>&1' _ "$UH"
  check "no process of ours is left" bash -c '! pgrep -f "lunepack-(runtime|service)" >/dev/null'
}

row_flipped_setup_and_parent() {
  row "13 a flipped byte in the setup file; R's parent group-writable"
  local setup bad rc snap
  setup=$(setup_of 1.0.0)
  bad=$W/setup/flipped
  cp "$setup" "$bad"
  python3 - "$bad" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
b[len(b) - 4096] ^= 1
open(p, 'wb').write(b)
PY
  chmod 755 "$bad"
  snap=$(footprint)
  rc=$(rc_of "$bad" --all-users --silent)
  eq "a flipped byte: verify (7)" "$rc" 7
  eq "nothing was written under /opt or /etc" "$(footprint)" "$snap"
  check "no staging folder" bash -c '! ls -d /opt/.lunepack-* >/dev/null 2>&1'
  # R's parent made group-writable: the engine refuses (not_protected).
  chgrp nogroup /opt
  chmod 775 /opt
  rc=$(rc_of "$setup" --all-users --silent)
  eq "a group-writable /opt: not_protected (35)" "$rc" 35
  check "nothing was installed" nothing_left
  chgrp root /opt
  chmod 755 /opt
  rc=$(rc_of "$setup" --all-users --silent)
  eq "with /opt restored the install works (0)" "$rc" 0
  chgrp nogroup /opt
  chmod 775 /opt
  rc=$(rc_of "$R/current/bin/lunepack-runtime" repair)
  eq "repair under a group-writable /opt: not_protected (35)" "$rc" 35
  chgrp root /opt
  chmod 755 /opt
  eq "repair works again (0)" "$(rc_of "$R/current/bin/lunepack-runtime" repair)" 0
  eq "uninstall (0)" "$(rc_of "$R/current/bin/lunepack-runtime" uninstall)" 0
  check "nothing is left" nothing_left
}

# ---- the run -----------------------------------------------------------------------------------

run_rows() {
  # One standard user, no password, no group of consequence; and the folder the suite works in.
  useradd -m -s /bin/bash "$UNAME"
  : >"$UOUT"
  chown "$UNAME" "$UOUT"
  install -d -m 755 /usr/local/bin /usr/local/share/applications
  setup_publisher
  publish 1.0.0 60

  row_static_packaging
  row_user_all_users_silent
  row_no_service_release
  row_root_install
  row_user_update_through_the_app
  row_user_update_through_the_cli
  row_crash_rollback
  row_supervisor_killed
  row_negatives
  row_socket
  row_policy
  row_service_switch
  row_uninstall
  row_pkexec
  row_flipped_setup_and_parent

  echo
  if [ "$FAILURES" -ne 0 ]; then
    echo "e2e-linux-machine: $FAILURES of $CHECKS checks failed" >&2
    exit 1
  fi
  echo "e2e-linux-machine: $CHECKS checks passed"
}
