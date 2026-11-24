#!/usr/bin/env bash
# The macOS per-machine end-to-end suite (M11 step 14, M11-D1): an app installed for all users by
# Apple's Installer from the `.pkg` the packager builds, then updated, health-checked, rolled back,
# refused, switched and uninstalled by the real runtime and the real update service under launchd,
# with a standard user driving the app. THIS SCRIPT CHANGES THE MACHINE IT RUNS ON: it installs a
# test app into /Applications, a LaunchDaemon into /Library/LaunchDaemons, a folder into
# /Library/Application Support/lunepack and creates one standard user, then removes all of them. Run
# it only on a disposable Mac or macOS VM (M11-D1 (a)); it is never part of the gate and never runs
# in CI.
#
#   sudo env LUNEPACK_E2E_MACHINE_OK=1 scripts/e2e-macos-machine.sh --disposable
#   scripts/e2e-macos-machine.sh --dry-run      list the rows; every real row is SKIPPED, nothing runs
#
# Guards, in this order (each is a refusal that touches nothing): the flag `--disposable`; the
# environment variable LUNEPACK_E2E_MACHINE_OK=1; macOS; root (through `sudo`, so that `SUDO_USER`
# names the administrator whose toolchain builds the binaries); and none of the paths the run owns
# exists.
# `sudo` removes the environment, so the variable goes through `env` as above.
#
# What it does: builds the release runtime, the update service, `lunepack` and the Rust example app
# as the administrator (not as root), packs 1.0.0 and the later versions as ad-hoc signed bundles
# with the service (the assemble flow), builds the setup files (`lunepack setup`: the `.dmg` and the
# `.pkg`), creates one standard user with a password made at run time (never printed, never written
# to a file, passed to `sysadminctl` once) and installs with `installer -pkg <pkg> -target /`. The
# rows then run as that user (`sudo -u`, an empty environment but HOME, PATH and the outcome file)
# or as root. A trap removes the daemon, its plist, the socket, the bundle, the install root, the
# policy file, the autostart entry, the user and the work folder, and the script FAILS when
# anything of them is left. Every external tool is bounded in time.
#
# Rows (the numbers are the Linux suite's, scripts/e2e-linux-machine.sh; M is macOS only):
#   0   static packaging: the `.pkg` and the `.dmg` of a release with the service; the payload
#       holds the two files; the reserved name is refused
#   10  `machine-install --pkg` as the standard user: usage, nothing written
#   1   `installer -pkg` as root: the install root, the bundle in /Applications, the record, the
#       LaunchDaemon (plist 0644 root:wheel, loaded), the socket 0666, the payload folder gone;
#       the user cannot write the bundle or the root; the user starts the app
#   M1  the Login Items / background item entry (`sfltool dumpbtm`, read only; recorded, not judged)
#   2   the user starts the app and it updates itself through the service, no prompt; the bundle
#       swap waits for the running app
#   3   the same through the runtime's command line with --json
#   4   a version that crashes on start and one that confirms too slowly (rollback, marked bad)
#   5   the supervisor killed after the apply: the fourth start past the lease rolls back
#   6   negatives as the standard user: flipped bytes in the pack, garbage and an oversize frame
#   7   the socket's mode tampered to 0600, a socket the user made at the endpoint
#   M2  the daemon disabled (`launchctl disable system/<label>`): service_unavailable, then enabled
#   8   the policy file: disable_self_update (33) and every broken variant
#   11  an old tree is kept while the user runs from it and collected after
#   11b an update by delta through the service (protocol version 2, M12): one file changes by 16
#       bytes, the packer writes the delta, the user's download fetches it as a patch and the
#       service stages it against its own tree; the update confirms
#   14  the package again: the same version repairs (installer exits 0), another version fails
#   12  uninstall: the user's own run shows the command (30); root's refused while the user runs
#       from the bundle (25), complete after; nothing left
#   15  the .NET example (examples/dotnet, M13 step 8) as the app, a bundle with the host alone in
#       Contents/MacOS and its managed files under Contents/Resources/app: installed by `.pkg`, the
#       standard user's update through the daemon, a version that crashes on start (rolled back,
#       not offered again), the fixed version, root's uninstall, nothing left; the bundle passes
#       `codesign --verify --deep --strict` after every step and carries no `com.apple.cs.*`
#       attribute. Needs the .NET SDK of examples/dotnet/global.json (its folder: LUNEPACK_E2E_DOTNET_DIR,
#       else the usual places); `dotnet` missing is a failure and LUNEPACK_E2E_DOTNET=0 skips the
#       row (SKIPPED). This row has not been run by an agent: it follows rows 2, 3, 4 and 12.
#
# The harness never prints an environment dump; a failed check names what differed (versions,
# outcome words, exit codes, modes). bash 3.2 compatible (the system bash).
# SC2016: `bash -c '...' _ args` keeps its program in single quotes on purpose (the arguments are
# the values). SC2012 and SC2010: names listed here are this suite's own, plain ASCII.
# shellcheck disable=SC2016,SC2012,SC2010
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: sudo env LUNEPACK_E2E_MACHINE_OK=1 scripts/e2e-macos-machine.sh --disposable" >&2
  echo "       scripts/e2e-macos-machine.sh --dry-run" >&2
}

die() {
  echo "e2e-macos-machine: $*" >&2
  exit 1
}

ROWS=(
  "0   static packaging (.pkg, .dmg, payload, reserved name)"
  "10  machine-install --pkg as the standard user (usage, nothing written)"
  "1   installer -pkg as root (root, bundle, daemon, socket, record)"
  "M1  Login Items entry (sfltool dumpbtm, read only)"
  "2   the user's app updates itself through the service; the swap waits for the running app"
  "3   the same through the runtime's command line (--json)"
  "4   a crashing version and a slow one are rolled back"
  "5   the supervisor killed after the apply"
  "6   negatives as the standard user (flipped bytes, garbage, oversize frame)"
  "7   a socket that is not the service's (mode 0600, a socket owned by the user)"
  "M2  the daemon disabled with launchctl: service_unavailable"
  "8   the administrator's policy file"
  "11  an old tree kept while the user runs from it"
  "11b an update by delta through the service (protocol version 2): the changed file arrives as a patch"
  "14  the package again (same version repairs, another version fails)"
  "12  uninstall (the user's command, root refused while in use, complete, nothing left)"
  "15  the .NET example app: install by .pkg, update through the daemon, crash and rollback, the fixed version, uninstall"
)

dry=0
disposable=0
while [ "$#" -gt 0 ]; do
  case $1 in
    --dry-run)
      dry=1
      shift
      ;;
    --disposable)
      disposable=1
      shift
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

if [ "$dry" -eq 1 ]; then
  [ "$disposable" -eq 0 ] || {
    usage
    exit 2
  }
  echo "e2e-macos-machine: dry run: nothing is built, installed or changed"
  for row in "${ROWS[@]}"; do
    echo "  SKIPPED  $row"
  done
  echo "e2e-macos-machine: ${#ROWS[@]} rows listed, all SKIPPED"
  exit 0
fi

# ---- the guards (each refuses before anything is touched) -------------------------------------

[ "$disposable" -eq 1 ] || die "refusing to run without --disposable (this suite changes /Applications and /Library; disposable machines only)"
[ "${LUNEPACK_E2E_MACHINE_OK:-}" = 1 ] || die "refusing to run: LUNEPACK_E2E_MACHINE_OK=1 is not set (this suite changes /Applications and /Library; disposable machines only)"
[ "$(uname -s)" = Darwin ] || die "refusing to run: macOS only (the Linux suite is scripts/e2e-linux-machine.sh)"
[ "$(id -u)" = 0 ] || die "refusing to run: it needs root (sudo env LUNEPACK_E2E_MACHINE_OK=1 scripts/e2e-macos-machine.sh --disposable)"
builder=${SUDO_USER:-}
[ -n "$builder" ] && [ "$builder" != root ] || die "refusing to run: SUDO_USER must name the administrator who builds (run it through sudo)"
id "$builder" >/dev/null 2>&1 || die "refusing to run: SUDO_USER does not name a user"
case $(uname -m) in
  arm64) target=macos-aarch64 ;;
  x86_64) target=macos-x86_64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
for tool in /usr/bin/hdiutil /usr/bin/codesign /usr/sbin/installer /usr/bin/pkgutil /bin/launchctl /usr/sbin/sysadminctl /usr/bin/dscl /usr/bin/python3 /usr/bin/perl /usr/bin/lsbom; do
  [ -x "$tool" ] || die "refusing to run: $tool is missing"
done

app_id=org.lunepack.e2emachine
app_name="Lunepack E2E Machine"
entry=lunepack-e2e-machine
label=lunepack-$app_id
pkg_id=$(printf '%s' "$app_id" | tr '_' '-').lunepack-machine
home_dir="/Library/Application Support/lunepack"
R="$home_dir/$app_id"
B="/Applications/$app_name.app"
plist=/Library/LaunchDaemons/$label.plist
sock=/var/run/lunepack-$app_id.sock
agent=/Library/LaunchAgents/lunepack-$app_id.autostart.plist
policy_dir="$home_dir/.policy"
policy_file="$policy_dir/$app_id.json"

# Nothing is touched when any name this run owns is already there.
for p in "$R" "$B" "$plist" "$sock" "$agent" "$policy_file"; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    die "refusing: $p already exists; nothing was touched"
  fi
done
home_existed=0
policy_dir_existed=0
[ -e "$home_dir" ] && home_existed=1
[ -e "$policy_dir" ] && policy_dir_existed=1

# Runs a command for at most $1 seconds (perl's alarm; stdin closed). Exit 124 on a timeout.
limited() {
  local secs=$1
  shift
  perl -e '
    my $secs = shift @ARGV;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) { setpgrp(0, 0); open(STDIN, "<", "/dev/null"); exec @ARGV or exit 127; }
    $SIG{ALRM} = sub { kill "KILL", -$pid; waitpid($pid, 0); exit 124; };
    $SIG{INT} = $SIG{TERM} = sub { kill "KILL", -$pid; waitpid($pid, 0); exit 130; };
    alarm $secs;
    waitpid($pid, 0);
    exit($? >> 8);
  ' "$secs" "$@"
}

# ---- state of the run -------------------------------------------------------------------------

bhome=$(dscl . -read "/Users/$builder" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
[ -d "$bhome" ] || die "the administrator's home is not a folder"
# Row 15 needs the .NET SDK: its folder is found before anything is made or touched.
dotnet_wanted=1
dotnet_dir=
if [ "${LUNEPACK_E2E_DOTNET:-1}" = 0 ]; then
  dotnet_wanted=0
else
  for d in "${LUNEPACK_E2E_DOTNET_DIR:-}" /opt/homebrew/bin /usr/local/share/dotnet /usr/local/bin "$bhome/.dotnet"; do
    if [ -n "$d" ] && [ -x "$d/dotnet" ]; then
      dotnet_dir=$d
      break
    fi
  done
  [ -n "$dotnet_dir" ] || die "refusing to run: dotnet was not found (LUNEPACK_E2E_DOTNET_DIR names its folder; LUNEPACK_E2E_DOTNET=0 skips row 15)"
fi
root=$(mktemp -d /private/tmp/lunepack-e2e-mac-machine.XXXXXX)
root=$(cd "$root" && pwd -P)
case $root in
  /private/tmp/lunepack-e2e-mac-machine.*) ;;
  *) die "bad work folder" ;;
esac
# The administrator builds and publishes; the standard user reads (755) and writes only `out`.
chown "$builder" "$root"
chmod 755 "$root"
mkdir -p "$root/build" "$root/work" "$root/pub" "$root/cli-home" "$root/release" "$root/setup" "$root/out"
chown -R "$builder" "$root/build" "$root/work" "$root/pub" "$root/cli-home" "$root/release" "$root/setup"
std=
std_home=
outcome=$root/out/outcome.txt
FAILURES=0
CHECKS=0
ROW=
armed=0

# ---- reporting --------------------------------------------------------------------------------

row() {
  ROW=$1
  echo "== row $1"
}

fail() {
  FAILURES=$((FAILURES + 1))
  echo "  FAIL [$ROW]: $1" >&2
}

check() { # LABEL COMMAND...
  local label=$1
  shift
  CHECKS=$((CHECKS + 1))
  if "$@"; then
    echo "  ok: $label"
  else
    fail "$label"
  fi
}

eq() { # LABEL ACTUAL EXPECTED
  CHECKS=$((CHECKS + 1))
  if [ "$2" = "$3" ]; then
    echo "  ok: $1"
  else
    fail "$1 (got '$2', want '$3')"
  fi
}

skipped() { # a row that cannot run here, by name
  echo "  SKIPPED: $1"
}

# ---- running things ---------------------------------------------------------------------------

# As the administrator (the builder), with an empty environment but their home, a PATH with their
# cargo, and what the build needs.
as_builder() {
  limited 3600 sudo -u "$builder" env -i HOME="$bhome" PATH="$bhome/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    CARGO_HOME="${CARGO_HOME_OF_BUILDER:-$bhome/.cargo}" RUSTUP_HOME="${RUSTUP_HOME_OF_BUILDER:-$bhome/.rustup}" "$@"
}

# As the standard user: an empty environment but HOME, PATH and the outcome file's name.
as_user() {
  limited 600 sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" "$@"
}

LAST_OUT=$root/last.out
LAST_ERR=$root/last.err
run() { # COMMAND...: stdout in $LAST_OUT, stderr in $LAST_ERR
  local rc=0
  "$@" >"$LAST_OUT" 2>"$LAST_ERR" </dev/null || rc=$?
  return "$rc"
}
rc_of() {
  local rc=0
  run "$@" || rc=$?
  echo "$rc"
}
# The last line of the last command's stdout as a JSON member (python: /usr/bin/python3, no jq).
last_member() { # MEMBER (dotted)
  /usr/bin/python3 - "$1" "$LAST_OUT" <<'PY'
import json, sys
path, name = sys.argv[2], sys.argv[1]
lines = [l for l in open(path).read().splitlines() if l.strip()]
try:
    value = json.loads(lines[-1])
    for part in name.split("."):
        value = value[part]
except Exception:
    sys.exit(0)
if value is None:
    sys.exit(0)
print("true" if value is True else "false" if value is False else value)
PY
}

wait_for() { # SECONDS COMMAND...
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

# ---- publishing -------------------------------------------------------------------------------

tdir=$bhome/.lunepack-e2e-machine-target-$$
cli() { (cd "$root/pub" && limited 600 sudo -u "$builder" env -i HOME="$root/cli-home" PATH=/usr/bin:/bin "$tdir/release/lunepack" "$@"); }
rd=$root/release
cfg=$root/pub/lunepack.toml
root_pub=
release_pub=

write_config() { # VERSION HEALTH_TIMEOUT
  cat >"$root/pub/release-$1.toml" <<EOF
app_id = "$app_id"

[root]
version = 1
threshold = 1
keys = ["$root_pub"]

[signers.root]
file = "root.key"

[signers.release]
file = "release.key"

[update]
feed = "file://$rd/"
channel = "stable"
health_timeout_secs = $2

[install]
entry = "Contents/MacOS/$entry"
name = "$app_name"
comment = "The lunepack machine end-to-end app"
EOF
  chown "$builder" "$root/pub/release-$1.toml"
}

sign_adhoc() {
  as_builder /usr/bin/codesign --force --sign - --timestamp=none "$1" >/dev/null 2>&1 ||
    die "codesign failed for ${1#"$root"/}"
}

# delta_file TWEAK OUT: 256 KiB of incompressible bytes, the same in every release but for 16 bytes
# in the middle that TWEAK sets (a number), so a patch from one release to another is a few dozen
# bytes against a frame of the file's size (M12 step 7). The base bytes are made once per run.
delta_file() {
  [ -e "$root/work/delta-base.bin" ] || head -c 262144 /dev/urandom >"$root/work/delta-base.bin"
  cp "$root/work/delta-base.bin" "$2"
  printf '%016d' "$1" | dd of="$2" bs=1 seek=131072 conv=notrunc 2>/dev/null
}

# publish VERSION HEALTH_TIMEOUT [FLAG...]: packs the signed bundle of that version, with the
# service, into the release directory and adds it to the feed. Flags are lines of `e2e-flags`.
# With DELTA_TWEAK set (`DELTA_TWEAK=1 publish ...`) the bundle also holds `Contents/Resources/delta.bin`.
publish() {
  local ver=$1 timeout=$2 flag input asm code
  shift 2
  input=$root/work/in-$ver
  asm=$root/work/assembled-$ver
  rm -rf "$input" "$asm"
  mkdir -p "$input/Contents/MacOS" "$input/Contents/Resources"
  cat >"$input/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$entry</string>
<key>CFBundleIdentifier</key><string>$app_id.app</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>$app_name</string>
<key>CFBundleShortVersionString</key><string>$ver</string>
</dict></plist>
EOF
  cp "$root/build/e2e_app" "$input/Contents/MacOS/$entry"
  chmod 755 "$input/Contents/MacOS/$entry"
  printf '%s\n' "$ver" >"$input/Contents/Resources/version.txt"
  if [ -n "${DELTA_TWEAK:-}" ]; then
    delta_file "$DELTA_TWEAK" "$input/Contents/Resources/delta.bin"
  fi
  for flag in "$@"; do
    printf '%s\n' "$flag" >>"$input/Contents/Resources/e2e-flags"
  done
  chown -R "$builder" "$input"
  write_config "$ver" "$timeout"
  cli pack --input "$input" --version "$ver" --target "$target" --runtime "$root/build/lunepack-runtime" \
    --service "$root/build/lunepack-service" --config "$root/pub/release-$ver.toml" --assemble "$asm" >/dev/null
  for code in "$asm/Contents/MacOS/lunepack-runtime" "$asm/Contents/MacOS/lunepack-service" "$asm"; do
    sign_adhoc "$code"
  done
  cli pack --input "$asm" --version "$ver" --target "$target" \
    --runtime "$asm/Contents/MacOS/lunepack-runtime" --service "$asm/Contents/MacOS/lunepack-service" \
    --config "$root/pub/release-$ver.toml" --release-dir "$rd" --sign release >/dev/null
  cli feed add --release-dir "$rd" --channel stable --version "$ver" --sign release --config "$cfg" >/dev/null
  chmod -R a+rX "$rd"
}

# publish_dotnet VERSION HEALTH_TIMEOUT [FLAG...]: as publish, for the .NET example's bundle (row 15):
# the host alone in Contents/MacOS, its managed files under Contents/Resources/app. Every Mach-O file
# of the assembled bundle is signed ad hoc, inner first (the runtime, the service, the loose
# libraries of Contents/Resources/app), then the bundle; `entry` is `Example` while the row runs.
publish_dotnet() {
  local ver=$1 timeout=$2 flag input asm code
  shift 2
  input=$root/work/in-$ver
  asm=$root/work/assembled-$ver
  rm -rf "$input" "$asm"
  cp -R "$root/build/Example.app" "$input"
  printf '%s\n' "$ver" >"$input/Contents/Resources/version.txt"
  for flag in "$@"; do
    printf '%s\n' "$flag" >>"$input/Contents/Resources/e2e-flags"
  done
  chown -R "$builder" "$input"
  write_config "$ver" "$timeout"
  cli pack --input "$input" --version "$ver" --target "$target" --runtime "$root/build/lunepack-runtime" \
    --service "$root/build/lunepack-service" --config "$root/pub/release-$ver.toml" --assemble "$asm" >/dev/null
  while IFS= read -r code; do
    if file -b "$code" | grep -q 'Mach-O'; then
      sign_adhoc "$code"
    fi
  done < <(find "$asm/Contents/Resources/app" -type f)
  for code in "$asm/Contents/MacOS/lunepack-runtime" "$asm/Contents/MacOS/lunepack-service" "$asm"; do
    sign_adhoc "$code"
  done
  cli pack --input "$asm" --version "$ver" --target "$target" \
    --runtime "$asm/Contents/MacOS/lunepack-runtime" --service "$asm/Contents/MacOS/lunepack-service" \
    --config "$root/pub/release-$ver.toml" --release-dir "$rd" --sign release >/dev/null
  cli feed add --release-dir "$rd" --channel stable --version "$ver" --sign release --config "$cfg" >/dev/null
  chmod -R a+rX "$rd"
}

# ---- what is installed ------------------------------------------------------------------------

version_of_bundle() {
  tr -d '[:space:]' <"$B/Contents/Resources/version.txt" 2>/dev/null || true
}
bundle_is() { [ "$(version_of_bundle)" = "$1" ]; }
daemon_loaded() { launchctl print "system/$label" >/dev/null 2>&1; }
outcomes() { cat "$outcome" 2>/dev/null || true; }
has_outcome() { outcomes | grep -qxF "$1"; }
reset_outcomes() {
  : >"$outcome"
  chown "$std" "$outcome"
}
mode_owner() { stat -f '%Lp %Su:%Sg' "$1"; }
footprint() {
  {
    find "$R" "$B" -xdev -exec stat -f '%N %HT %Lp %u:%g' {} + 2>/dev/null | grep -v '/.lunepack/state/' | grep -v '/.lunepack/logs/' || true
    ls -1 /Library/LaunchDaemons | grep '^lunepack-' || true
  } | sort
}
# The names this run owns that exist now.
leftovers() {
  local p left=""
  for p in "$R" "$B" "$plist" "$sock" "$agent" "$policy_file"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      left="$left $p"
    fi
  done
  if ls -d "$home_dir"/.lunepack-install-* "$home_dir"/.lunepack-uninstall-* "$home_dir/.installer/$app_id" >/dev/null 2>&1; then
    left="$left (a staging or uninstall folder)"
  fi
  if daemon_loaded; then
    left="$left (the daemon is loaded)"
  fi
  printf '%s' "$left"
}
nothing_left() { [ -z "$(leftovers)" ]; }

app_start() { # ARGS...: the standard user starts the installed app, detached
  sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
    "$B/Contents/MacOS/$entry" "$@" >/dev/null 2>&1 </dev/null
}

# A raw client of the socket (python3): prints the bytes' fate.
sock_client() { # PATH HEX
  sudo -u "$std" /usr/bin/python3 - "$1" "$2" <<'PY'
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

# ---- cleanup (the trap): removes what this run made, then FAILS on a leftover -----------------

cleanup() {
  local status=$? left
  trap - EXIT
  if [ "$armed" -eq 1 ]; then
    # What still runs from the bundle, the root or the work folder.
    ps -axo pid=,args= 2>/dev/null | awk -v b="$B/" -v r="$R/" -v w="$root/" -v me="$$" '
      $1 != me && (index($0, b) > 0 || index($0, r) > 0 || index($0, w) > 0) && index($0, "awk -v") == 0 { print $1 }
    ' | while IFS= read -r pid; do kill "$pid" 2>/dev/null || true; done
    launchctl bootout "system/$label" >/dev/null 2>&1 || true
    launchctl enable "system/$label" >/dev/null 2>&1 || true
    rm -f "$plist" "$sock" "$agent" "$policy_file"
    if [ "$policy_dir_existed" -eq 0 ]; then rmdir "$policy_dir" 2>/dev/null || true; fi
    rm -rf "$R" "$B" "$home_dir/.installer/$app_id"
    rm -rf "$home_dir"/.lunepack-install-* "$home_dir"/.lunepack-uninstall-* 2>/dev/null || true
    rmdir "$home_dir/.installer" 2>/dev/null || true
    if [ "$home_existed" -eq 0 ]; then rmdir "$home_dir" 2>/dev/null || true; fi
    pkgutil --forget "$pkg_id" >/dev/null 2>&1 || true
    if [ -n "$std" ]; then
      sysadminctl -deleteUser "$std" >/dev/null 2>&1 || true
      dscl . -delete "/Users/$std" >/dev/null 2>&1 || true
      rm -rf "$std_home"
    fi
  fi
  rm -rf "$tdir" "$root"
  left=$(leftovers)
  if [ -n "$std" ] && id "$std" >/dev/null 2>&1; then
    left="$left (the user $std)"
  fi
  if [ -n "$left" ]; then
    echo "e2e-macos-machine: FAILED: left over:$left" >&2
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT
armed=1

# ---- build ------------------------------------------------------------------------------------

echo "e2e-macos-machine: building the binaries as $builder (not as root)"
as_builder env CARGO_TARGET_DIR="$tdir" sh -c "cd '$top' && ./scripts/build-runtime.sh $target --out '$root/build/lunepack-runtime'"
as_builder env CARGO_TARGET_DIR="$tdir" sh -c "cd '$top' && cargo build --locked --release -p lunepack-cli -p lunepack-service && cargo build --locked --release -p lunepack --example e2e_app"
cp "$tdir/release/lunepack-service" "$root/build/lunepack-service"
cp "$tdir/release/examples/e2e_app" "$root/build/e2e_app"
chown -R "$builder" "$root/build"
chmod -R a+rX "$root/build"
for f in "$root/build/lunepack-runtime" "$root/build/lunepack-service" "$root/build/e2e_app" "$tdir/release/lunepack"; do
  [ -f "$f" ] || die "the build left no ${f##*/}"
done
if [ "$dotnet_wanted" -eq 1 ]; then
  # The .NET example for this Mac's own target (a thin runtime: never macos-universal), as a bundle.
  as_builder env PATH="$dotnet_dir:$bhome/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    sh -c "cd '$top' && ./scripts/build-example-dotnet.sh $target '$root/build/dotnet' --macos-bundle '$root/build/Example.app'"
  [ -x "$root/build/Example.app/Contents/MacOS/Example" ] || die "the build left no .NET bundle"
  chown -R "$builder" "$root/build"
  chmod -R a+rX "$root/build"
fi

# ---- the publisher and the first release ----------------------------------------------------------

public_of() { cli keys gen "$root/pub/$1.key" | sed -n 's/^public: //p' | head -n 1 | tr -d '[:space:]'; }
root_pub=$(public_of root)
release_pub=$(public_of release)
[ -n "$root_pub" ] && [ -n "$release_pub" ] || die "keys gen printed no public key"
cli init --app-id "$app_id" --root-key "$root_pub" --config "$cfg" >/dev/null
write_config 1.0.0 60
cp "$root/pub/release-1.0.0.toml" "$cfg"
chown "$builder" "$cfg"
cli keys set --release-dir "$rd" --release-key "$release_pub" --sign root --config "$cfg" >/dev/null
publish 1.0.0 60
pkg=$root/setup/$app_id-1.0.0-$target.pkg
dmg=$root/setup/$app_id-1.0.0-$target.dmg
cli setup "$rd" --version 1.0.0 --target "$target" --out "$dmg" --config "$cfg" >/dev/null
[ -s "$pkg" ] || die "setup left no .pkg beside the .dmg"
chmod -R a+rX "$root/setup"

# ---- the standard user (a password made now, never printed or stored) --------------------------

std=lpm$(date +%s | tail -c 6)
std_home=/Users/$std
pw=$(/usr/bin/python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
sysadminctl -addUser "$std" -fullName "Lunepack Machine E2E" -password "$pw" -home "$std_home" >/dev/null 2>&1 || true
if ! id "$std" >/dev/null 2>&1; then
  dscl . -create "/Users/$std"
  dscl . -create "/Users/$std" UserShell /bin/bash
  dscl . -create "/Users/$std" RealName "Lunepack Machine E2E"
  dscl . -create "/Users/$std" UniqueID 598
  dscl . -create "/Users/$std" PrimaryGroupID 20
  dscl . -create "/Users/$std" NFSHomeDirectory "$std_home"
fi
pw=
id "$std" >/dev/null 2>&1 || die "the standard user was not created"
if id -Gn "$std" | tr ' ' '\n' | grep -qx admin; then
  die "the standard user is an administrator"
fi
[ -d "$std_home" ] || install -d -m 700 -o "$std" "$std_home"
chown "$std" "$root/out"
echo "e2e-macos-machine: the standard user exists (uid $(id -u "$std"))"

# ============================================================================== the rows ==========

row "0 static packaging"
payload=$(pkgutil --payload-files "$pkg" 2>/dev/null | grep -v '/$' | grep -vx '\.' | sed 's|^\./||' | sort | tr '\n' ' ')
check "the payload is the two files of the first install" bash -c '[ "$(printf "%s" "$1" | tr " " "\n" | grep -cE "lunepack-runtime|lunepack-setup.payload")" = 2 ]' _ "$payload"
check "the package says it is unsigned (local, ad hoc)" bash -c 'pkgutil --check-signature "$1" 2>&1 | grep -qi "no signature"' _ "$pkg"
mkdir -p "$root/work/in-reserved/Contents/MacOS"
cp "$root/build/e2e_app" "$root/work/in-reserved/Contents/MacOS/$entry"
cp "$root/build/lunepack-service" "$root/work/in-reserved/Contents/MacOS/lunepack-service"
chown -R "$builder" "$root/work/in-reserved"
rc=$(rc_of cli pack --input "$root/work/in-reserved" --version 0.9.0 --target "$target" --runtime "$root/build/lunepack-runtime" --service "$root/build/lunepack-service" --config "$root/pub/release-1.0.0.toml" --assemble "$root/work/asm-reserved")
check "the service's name is reserved (exit $rc)" test "$rc" -ne 0
check "packaging wrote nothing under /Applications or the machine home" nothing_left

row "10 machine-install --pkg as the standard user"
before=$(footprint)
runtime_in_pkg="$root/build/lunepack-runtime"
eq "usage (2), not root" "$(rc_of as_user "$runtime_in_pkg" machine-install --pkg)" 2
eq "nothing was written" "$(footprint)" "$before"
check "nothing left" nothing_left

row "1 installer -pkg as root"
rc=$(rc_of limited 600 installer -pkg "$pkg" -target /)
eq "installer exits 0" "$rc" 0
eq "the package's folder is gone" "$(ls -d "$home_dir/.installer/$app_id" 2>/dev/null | wc -l | tr -d ' ')" 0
check "the bundle is in /Applications" test -d "$B"
eq "the bundle is version 1.0.0" "$(version_of_bundle)" 1.0.0
check "the install root is there" test -d "$R/.lunepack/state"
eq "the install root is root's, not writable by others" "$(mode_owner "$R" | cut -d' ' -f1)" 755
check "the machine folder is root's alone" bash -c '[ "$(stat -f "%Lp %u" "$1")" = "700 0" ]' _ "$R/.lunepack/machine"
check "the daemon plist exists (0644 root:wheel)" bash -c '[ "$(stat -f "%Lp %Su:%Sg" "$1")" = "644 root:wheel" ]' _ "$plist"
check "the daemon is registered with launchd" daemon_loaded
check "the socket is there" test -S "$sock"
eq "the socket's mode" "$(stat -f '%Lp' "$sock")" 666
check "the staging folders are gone" bash -c '! ls -d "$1"/.lunepack-install-* >/dev/null 2>&1' _ "$home_dir"
check "the user cannot write the bundle" bash -c '! sudo -u "$1" touch "$2/Contents/x" 2>/dev/null' _ "$std" "$B"
check "the user cannot write the install root" bash -c '! sudo -u "$1" touch "$2/x" 2>/dev/null' _ "$std" "$R"
check "the user cannot read the machine folder" bash -c '! sudo -u "$1" ls "$2/.lunepack/machine" >/dev/null 2>&1' _ "$std" "$R"
reset_outcomes
check "the user starts the app" as_user "$B/Contents/MacOS/$entry"
check "and it confirmed or had nothing pending" bash -c 'grep -qE "^1.0.0 (confirmed|nothing-pending)$" "$1"' _ "$outcome"

row "M1 Login Items entry (read only)"
if [ -x /usr/bin/sfltool ]; then
  btm=$(limited 60 /usr/bin/sfltool dumpbtm 2>/dev/null | grep -c "$label" || true)
  echo "  recorded: sfltool dumpbtm lists $label ${btm:-0} time(s) (not judged here; the person check looks at System Settings)"
else
  skipped "sfltool is not on this system"
fi

row "2 the user's app updates through the service"
publish 1.1.0 60
reset_outcomes
# The app updates itself and exits; the swap waits for it.
app_start --update --no-ui || true
check "the app scheduled the update" wait_for 60 has_outcome "1.0.0 apply-scheduled"
check "the new version confirmed through the service" wait_for 120 has_outcome "1.1.0 confirmed"
eq "the bundle holds 1.1.0 at the same path" "$(version_of_bundle)" 1.1.0
check "the bundle is still one the user can run" as_user test -x "$B/Contents/MacOS/$entry"
check "no process of the old tree is left" bash -c '! pgrep -f "$1/app/1.0.0" >/dev/null' _ "$R"

row "3 the same through the runtime's command line"
publish 1.2.0 60
rt=$B/Contents/MacOS/lunepack-runtime
run as_user "$rt" check --json
eq "check finds 1.2.0" "$(last_member update.version)" 1.2.0
run as_user "$rt" download --json --expect-version 1.2.0
eq "download stages it" "$(last_member staged)" true
reset_outcomes
(sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
  sh -c "sleep 2 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.2.0 --no-ui -- --after-update" \
  >/dev/null 2>&1 </dev/null) || true
check "the new app ran and confirmed" wait_for 120 has_outcome "1.2.0 confirmed"
eq "the bundle holds 1.2.0" "$(version_of_bundle)" 1.2.0

row "4 a crashing version and a slow one"
publish 1.3.0 20 crash-on-start
run as_user "$rt" download --json --expect-version 1.3.0
reset_outcomes
(sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
  sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.3.0 --no-ui" \
  >/dev/null 2>&1 </dev/null) || true
check "the bad version crashed on start" wait_for 120 has_outcome "1.3.0 crash"
check "and the old one came back" wait_for 120 has_outcome "1.2.0 start"
eq "the bundle is back to 1.2.0" "$(version_of_bundle)" 1.2.0
run as_user "$rt" check --json
eq "the bad version is not offered again" "$(last_member update)" ""
publish 1.4.0 5 'slow-confirm 30'
run as_user "$rt" download --json --expect-version 1.4.0
reset_outcomes
(sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
  sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.4.0 --no-ui" \
  >/dev/null 2>&1 </dev/null) || true
check "the slow version started" wait_for 120 has_outcome "1.4.0 slow-confirm"
check "and was rolled back before it confirmed" wait_for 120 bundle_is 1.2.0
check "it never confirmed" bash -c '! grep -qx "1.4.0 confirmed" "$1"' _ "$outcome"

row "5 the supervisor killed after the apply"
publish 1.5.0 10 'slow-confirm 120'
run as_user "$rt" download --json --expect-version 1.5.0
reset_outcomes
(sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
  sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 1.5.0 --no-ui" \
  >/dev/null 2>&1 </dev/null) || true
check "the new version started" wait_for 120 has_outcome "1.5.0 slow-confirm"
pkill -9 -u "$std" -f 'lunepack-runtime apply' || true
pkill -9 -u "$std" -f "$entry" || true
sleep 1
eq "the version is still the pending one" "$(version_of_bundle)" 1.5.0
try_start() { limited 6 sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" "$B/Contents/MacOS/$entry" >/dev/null 2>&1 </dev/null || true; }
try_start
try_start
eq "starts inside the lease roll nothing back" "$(version_of_bundle)" 1.5.0
for i in 1 2 3; do
  sleep 26
  try_start
  eq "counted start $i keeps the pending version" "$(version_of_bundle)" 1.5.0
done
sleep 26
try_start
check "the fourth start past a lease rolls back in the service" wait_for 60 bundle_is 1.2.0

row "6 negatives as the standard user"
publish 1.6.0 60
file=$(find "$rd" -path "*1.6.0*" -name '*.pack' | head -n 1)
cp "$file" "$root/pack.bak"
/usr/bin/python3 - "$file" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
for i in range(100, len(b), 97):
    b[i] ^= 1
open(p, 'wb').write(b)
PY
snap=$(footprint)
eq "flipped bytes in the pack are verify (7)" "$(rc_of as_user "$rt" download --json --expect-version 1.6.0)" 7
eq "nothing changed under R or the bundle" "$(footprint)" "$snap"
cp "$root/pack.bak" "$file"
chmod a+r "$file"
run sock_client "$sock" "$(/usr/bin/python3 -c 'print(b"this is not a frame\n".hex())')"
check "garbage: the connection ended without a crash" grep -q '^connected' "$LAST_OUT"
run sock_client "$sock" "$(/usr/bin/python3 -c 'print((b"\xff\xff\xff\xff" + b"a" * 64).hex())')"
check "an oversize frame: the connection ended" grep -q '^connected' "$LAST_OUT"
check "the daemon is still registered" daemon_loaded
eq "updates still work" "$(rc_of as_user "$rt" download --json --expect-version 1.6.0)" 0
check "the user cannot unload the daemon" bash -c '! sudo -u "$1" launchctl bootout "system/$2" >/dev/null 2>&1' _ "$std" "$label"
check "the user cannot edit the plist" bash -c '! sudo -u "$1" sh -c "echo x >> \"$2\"" 2>/dev/null' _ "$std" "$plist"

row "7 a socket that is not the service's"
chmod 600 "$sock"
rc=$(rc_of as_user "$rt" download --json --expect-version 1.6.0)
check "a socket of mode 0600 is refused (exit $rc)" test "$rc" -ne 0
chmod 666 "$sock"
eq "updates work again" "$(rc_of as_user "$rt" download --json --expect-version 1.6.0)" 0
launchctl bootout "system/$label" >/dev/null 2>&1 || true
rm -f "$sock"
/usr/bin/python3 - "$sock" "$std" "$root/fake-got" <<'PY' &
import os, pwd, socket, sys
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
fake=$!
wait_for 10 test -S "$sock" || true
rc=$(rc_of as_user "$rt" download --json --expect-version 1.6.0)
check "a fake socket owned by the user is refused (exit $rc)" test "$rc" -ne 0
kill "$fake" 2>/dev/null || true
wait "$fake" 2>/dev/null || true
eq "the fake service received nothing" "$(cat "$root/fake-got" 2>/dev/null || echo 0)" 0
rm -f "$sock" "$root/fake-got"
launchctl bootstrap system "$plist" >/dev/null 2>&1 || true
wait_for 20 test -S "$sock" || true
eq "updates work again with the real socket" "$(rc_of as_user "$rt" download --json --expect-version 1.6.0)" 0

row "M2 the daemon disabled with launchctl"
launchctl bootout "system/$label" >/dev/null 2>&1 || true
launchctl disable "system/$label" >/dev/null 2>&1 || true
rm -f "$sock"
rc=$(rc_of as_user "$rt" download --json --expect-version 1.6.0)
check "with the daemon disabled the download is refused (exit $rc)" test "$rc" -ne 0
eq "its error is the service being unavailable" "$(last_member kind)" service_unavailable
launchctl enable "system/$label" >/dev/null 2>&1 || true
launchctl bootstrap system "$plist" >/dev/null 2>&1 || true
wait_for 20 test -S "$sock" || true
eq "enabled again, updates work" "$(rc_of as_user "$rt" download --json --expect-version 1.6.0)" 0

row "8 the administrator's policy file"
mkdir -p "$policy_dir"
chown root:wheel "$home_dir" "$policy_dir" 2>/dev/null || true
chmod 755 "$policy_dir"
publish 1.7.0 60
policy() { # BODY [OWNER]
  printf '%s' "$1" >"$policy_file"
  chmod 644 "$policy_file"
  chown "${2:-root:wheel}" "$policy_file"
}
policy '{"disable_self_update":true}'
eq "disable_self_update is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
for body in '{"disable_self_update":false,"disable_self_update":false}' '{"unknown":true}' \
  '{"no_update_ui":"yes"}' 'not json' '[]' ''; do
  policy "$body"
  eq "a broken policy ($body) is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
done
policy '{"no_update_ui":false}' "$std:staff"
eq "a policy owned by the user is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
policy '{"no_update_ui":false}'
chmod 664 "$policy_file"
eq "a group-writable policy is 33" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 33
policy '{"no_update_ui":true}'
eq "no_update_ui alone: the download works" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 0
rm -f "$policy_file"
eq "no policy file: the download works" "$(rc_of as_user "$rt" download --json --expect-version 1.7.0)" 0

row "11 an old tree kept while the user runs from it"
old=$(version_of_bundle)
# The user keeps a process in the parked tree of the version before (its working directory).
parked=$R/app/$old
if [ -d "$parked" ]; then
  sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin sh -c "cd '$parked' && exec sleep 300" </dev/null >/dev/null 2>&1 &
  holder=$!
  sleep 1
else
  holder=
  skipped "no parked tree of $old to hold"
fi
update_to() { # VERSION
  publish "$1" 60
  run as_user "$B/Contents/MacOS/lunepack-runtime" download --json --expect-version "$1"
  reset_outcomes
  (sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
    sh -c "sleep 1 & exec \"$B/Contents/MacOS/lunepack-runtime\" apply-and-restart --json --wait-pid \$! --expect-version $1 --no-ui -- --after-update" \
    >/dev/null 2>&1 </dev/null) || true
  wait_for 120 has_outcome "$1 confirmed"
}
check "1.8.0 confirmed" update_to 1.8.0
check "1.9.0 confirmed" update_to 1.9.0
eq "the bundle holds 1.9.0" "$(version_of_bundle)" 1.9.0
if [ -n "$holder" ]; then
  check "the tree the user runs from is kept" test -d "$parked"
  kill "$holder" 2>/dev/null || true
  wait "$holder" 2>/dev/null || true
  check "1.9.1 confirmed" update_to 1.9.1
  check "the old tree is collected once nobody runs from it" wait_for 60 bash -c "[ ! -e '$parked' ]"
fi

row "11b the user's app updates by delta through the service (protocol version 2)"
# 1.9.2 brings Contents/Resources/delta.bin; 1.9.3 changes 16 bytes of it. The packer writes a delta
# from 1.9.2, the user's download fetches the file as a patch, the service stages it against its own
# tree and the update confirms.
DELTA_TWEAK=0 publish 1.9.2 60
run as_user "$B/Contents/MacOS/lunepack-runtime" download --json --expect-version 1.9.2
eq "download stages 1.9.2" "$(last_member staged)" true
reset_outcomes
(sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
  sh -c "sleep 1 & exec \"$B/Contents/MacOS/lunepack-runtime\" apply-and-restart --json --wait-pid \$! --expect-version 1.9.2 --no-ui -- --after-update" \
  >/dev/null 2>&1 </dev/null) || true
check "1.9.2 confirmed" wait_for 120 has_outcome "1.9.2 confirmed"
DELTA_TWEAK=7 publish 1.9.3 60
check "the packer wrote the delta from 1.9.2" test -s "$rd/1.9.3/$target.from-1.9.2.delta"
run as_user "$B/Contents/MacOS/lunepack-runtime" download --json --expect-version 1.9.3
eq "download stages 1.9.3" "$(last_member staged)" true
# The runtime writes at most ten progress lines a second (and a phase's last one), so the file's own
# `stage` line may be missing: the download's size says it was a patch, and any line that is there
# names the patch.
fetched=$(/usr/bin/python3 - "$LAST_OUT" <<'PY'
import json, sys
done = -1
for line in open(sys.argv[1]):
    o = json.loads(line)
    if o.get("type") == "progress" and o.get("phase") == "download":
        done = o["done"]
print(done)
PY
)
check "the download fetched a patch, not the file's frame ($fetched bytes)" test "$fetched" -ge 0 -a "$fetched" -lt 65536
check "every stage line of delta.bin names the patch" bash -c '! grep -F "\"phase\":\"stage\"" "$1" | grep -F "\"file\":{\"path\":\"Contents/Resources/delta.bin\"," | grep -qvF "\"source\":\"patch\""' _ "$LAST_OUT"
reset_outcomes
(sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
  sh -c "sleep 1 & exec \"$B/Contents/MacOS/lunepack-runtime\" apply-and-restart --json --wait-pid \$! --expect-version 1.9.3 --no-ui -- --after-update" \
  >/dev/null 2>&1 </dev/null) || true
check "1.9.3 confirmed" wait_for 120 has_outcome "1.9.3 confirmed"
eq "the bundle holds 1.9.3" "$(version_of_bundle)" 1.9.3
check "the bundle's delta.bin is the new one" cmp -s "$B/Contents/Resources/delta.bin" "$root/work/in-1.9.3/Contents/Resources/delta.bin"

row "14 the package again"
installed_version=$(version_of_bundle)
publish_pkg_of() { # VERSION: the .pkg of a published version
  cli setup "$rd" --version "$1" --target "$target" --out "$root/setup/$app_id-$1-$target.dmg" --config "$cfg" >/dev/null
  chmod -R a+rX "$root/setup"
  echo "$root/setup/$app_id-$1-$target.pkg"
}
same=$(publish_pkg_of "$installed_version")
eq "the package of the installed version repairs (installer exits 0)" "$(rc_of limited 600 installer -pkg "$same" -target /)" 0
eq "the bundle is unchanged" "$(version_of_bundle)" "$installed_version"
other=$(publish_pkg_of 1.0.0)
rc=$(rc_of limited 600 installer -pkg "$other" -target /)
check "the package of another version fails visibly (exit $rc)" test "$rc" -ne 0
eq "the bundle is unchanged after it" "$(version_of_bundle)" "$installed_version"
check "no payload folder is left" bash -c '! ls -d "$1/.installer/$2" >/dev/null 2>&1' _ "$home_dir" "$app_id"

row "12 uninstall"
rt=$B/Contents/MacOS/lunepack-runtime
snap=$(footprint)
# The standard user's own run asks for nothing and shows the command (30); nothing changes.
eq "the user's uninstall is elevation_required (30)" "$(rc_of as_user "$rt" uninstall)" 30
eq "nothing changed" "$(footprint)" "$snap"
# Root's run is refused while the user runs from the bundle.
sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin sh -c "cd '$B/Contents/MacOS' && exec sleep 60" </dev/null >/dev/null 2>&1 &
keeper=$!
sleep 1
eq "refused while the user runs from the bundle (in_use, 25)" "$(rc_of "$rt" uninstall)" 25
eq "nothing changed" "$(footprint)" "$snap"
check "no uninstall folder is left" bash -c '! ls -d "$1"/.lunepack-uninstall-* >/dev/null 2>&1' _ "$home_dir"
kill "$keeper" 2>/dev/null || true
wait "$keeper" 2>/dev/null || true
sleep 1
eq "complete when nothing runs from the bundle (0)" "$(rc_of "$rt" uninstall)" 0
check "nothing of the install is left" nothing_left
check "no process of ours is left" bash -c '! pgrep -f "lunepack-(runtime|service)" >/dev/null'

row "15 the .NET example app"
if [ "$dotnet_wanted" -eq 0 ]; then
  skipped "the .NET row (LUNEPACK_E2E_DOTNET=0)"
else
  entry=Example
  # Strict verification and no signature kept in an extended attribute (M13-D12), after every step.
  sealed() { # WHAT
    check "the bundle verifies strictly $1" bash -c '/usr/bin/codesign --verify --deep --strict "$1" >/dev/null 2>&1' _ "$B"
    check "no file of the bundle carries a com.apple.cs attribute $1" bash -c '! /usr/bin/xattr -lr "$1" 2>/dev/null | grep -q "com.apple.cs"' _ "$B"
  }
  publish_dotnet 2.0.0 60
  pkg15=$root/setup/$app_id-2.0.0-$target.pkg
  cli setup "$rd" --version 2.0.0 --target "$target" --out "$root/setup/$app_id-2.0.0-$target.dmg" --config "$cfg" >/dev/null
  chmod -R a+rX "$root/setup"
  eq "installer exits 0" "$(rc_of limited 600 installer -pkg "$pkg15" -target /)" 0
  eq "the bundle is version 2.0.0" "$(version_of_bundle)" 2.0.0
  check "the host is alone in Contents/MacOS besides the runtime and the service" bash -c '[ "$(ls "$1/Contents/MacOS" | sort | tr "\n" " ")" = "Example lunepack-runtime lunepack-service " ]' _ "$B"
  check "the example's managed files are under Contents/Resources/app" test -f "$B/Contents/Resources/app/Example.dll"
  sealed "after the install"
  reset_outcomes
  check "the user starts the app" as_user "$B/Contents/MacOS/Example"
  check "and it confirmed or had nothing pending" bash -c 'grep -qE "^2.0.0 (confirmed|nothing-pending)$" "$1"' _ "$outcome"

  # The user's update through the daemon, with no prompt.
  publish_dotnet 2.1.0 60
  reset_outcomes
  app_start --update --no-ui || true
  check "the app scheduled the update" wait_for 60 has_outcome "2.0.0 apply-scheduled"
  check "the new version confirmed through the service" wait_for 120 has_outcome "2.1.0 confirmed"
  eq "the bundle holds 2.1.0 at the same path" "$(version_of_bundle)" 2.1.0
  sealed "after the update"

  # A version that crashes on start: rolled back, marked bad, not offered again.
  rt=$B/Contents/MacOS/lunepack-runtime
  publish_dotnet 2.2.0 20 crash-on-start
  run as_user "$rt" download --json --expect-version 2.2.0
  reset_outcomes
  (sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
    sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 2.2.0 --no-ui" \
    >/dev/null 2>&1 </dev/null) || true
  check "the bad version crashed on start" wait_for 120 has_outcome "2.2.0 crash"
  check "and the old one came back" wait_for 120 has_outcome "2.1.0 start"
  eq "the bundle is back to 2.1.0" "$(version_of_bundle)" 2.1.0
  run as_user "$rt" check --json
  eq "the bad version is not offered again" "$(last_member update)" ""
  sealed "after the rollback"

  # The fixed version.
  publish_dotnet 2.3.0 60
  run as_user "$rt" download --json --expect-version 2.3.0
  reset_outcomes
  (sudo -u "$std" env -i HOME="$std_home" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outcome" \
    sh -c "sleep 1 & exec \"$rt\" apply-and-restart --json --wait-pid \$! --expect-version 2.3.0 --no-ui -- --after-update" \
    >/dev/null 2>&1 </dev/null) || true
  check "the fixed version confirmed" wait_for 120 has_outcome "2.3.0 confirmed"
  eq "the bundle holds 2.3.0" "$(version_of_bundle)" 2.3.0
  sealed "after the fixed version"

  # Root's uninstall, with nothing running from the bundle.
  sleep 1
  eq "uninstall (0)" "$(rc_of "$rt" uninstall)" 0
  check "nothing of the install is left" nothing_left
  check "no process of ours is left" bash -c '! pgrep -f "lunepack-(runtime|service)" >/dev/null'
  entry=lunepack-e2e-machine
fi

echo
if [ "$FAILURES" -ne 0 ]; then
  echo "e2e-macos-machine: $FAILURES of $CHECKS checks failed" >&2
  exit 1
fi
echo "e2e-macos-machine: $CHECKS checks passed"
