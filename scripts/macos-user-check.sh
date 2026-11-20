#!/usr/bin/env bash
# The user-run check of the macOS installer and updater (M8 step 12; roadmap P4). CI cannot see
# what Gatekeeper, App Management, "background item" notices or the Dock show, so a person walks
# the real flow once on a real Mac and answers a few questions; the answers go to a report.
#
#   scripts/macos-user-check.sh [--no-gui | --real-applications]
#
# It builds the runtime, the command line, the real `lunepack-ui` and the example app, packs the
# example 1.0.0, 1.1.0 and 1.2.0 as ad-hoc signed bundles (the assemble flow, M8-D8), builds the
# `.dmg` and the `.zip` of 1.0.0 and serves the feed from a loopback HTTP server. Then, with the
# user in front of the screen (about 15 minutes):
#   A. the installer app, opened through LaunchServices from the mounted `.dmg`: install with its
#      window;
#   B. start the installed app;
#   C. update to 1.1.0 with `apply-and-restart` (the update window, the swap, the relaunch), while
#      another app is in front: did the relaunched app take focus (expected: it may);
#   D. update to 1.2.0 with `apply-and-restart --background`, the same way (expected: no);
#   E. uninstall with the window;
#   F. a bundle taken out of the `.zip` into `<home>/Applications`, started, adopted by `check`.
# At each stage it asks whether a Gatekeeper, App Management, background-item or any other prompt
# appeared, and, for the windows, whether the Dock showed the right name. The answers, with the
# exit codes and the verdicts of `codesign`, `spctl` and `xattr` on the installed bundle, go to a
# report in the root; the report is printed at the end.
#
# Everything lives under one `mktemp -d` root (canonical): `HOME` of every lunepack process is
# `<root>/home`, the disk image is mounted under the root (never in /Volumes), and the trap detaches
# it, stops what still runs from under the root, unregisters the bundles LaunchServices saw
# (`lsregister -u`) and removes the root. No sudo, no signing identity (ad-hoc only), nothing
# outside the root is written except LaunchServices' own records of the temp bundles, which the
# trap removes. Every external call is bounded; the report holds no path outside the root and no
# environment.
#
#   --no-gui              build, pack and serve, then run the whole flow once without any window
#                         (a `--silent` install from the mounted image, `check`, `uninstall
#                         --silent`) and stop: no `open`, no question, no terminal needed.
#   --real-applications   run the same walk with the real home: the app is installed under the real
#                         ~/Applications and ~/Library/Application Support (app id
#                         org.lunepack.usercheck), and uninstalled by the walk's last stage (and by
#                         the trap if the walk stops early). Asks again before acting; refuses when
#                         either name is already there, and removes only what it installed.
#
# bash 3.2 compatible.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: scripts/macos-user-check.sh [--no-gui | --real-applications]" >&2
}

die() {
  echo "macos-user-check: $*" >&2
  exit 1
}

no_gui=0
real_apps=0
while [ "$#" -gt 0 ]; do
  case $1 in
    --no-gui)
      no_gui=1
      shift
      ;;
    --real-applications)
      real_apps=1
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
if [ "$no_gui" -eq 1 ] && [ "$real_apps" -eq 1 ]; then
  usage
  exit 2
fi

[ "$(uname -s)" = Darwin ] || die "refusing to run: macOS only (a person at a Mac walks the installer)"
if [ "$(id -u)" = 0 ]; then
  die "refusing to run as root"
fi
if [ "$no_gui" -eq 0 ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
  die "refusing to run without a terminal: the walk asks questions (use --no-gui for the build and a headless pass)"
fi
case $(uname -m) in
  arm64) target=macos-aarch64 ;;
  x86_64) target=macos-x86_64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
for tool in /usr/bin/hdiutil /usr/bin/codesign /usr/bin/open /usr/bin/python3 /usr/bin/perl /usr/bin/ditto /usr/bin/xattr /usr/bin/curl; do
  [ -x "$tool" ] || die "$tool is missing"
done

app_id=org.lunepack.usercheck
app_name="Lunepack User Check"
entry=lunepack-usercheck
lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

# Runs a command for at most $1 seconds (perl's alarm; stdin closed; its own process group, killed
# whole on a timeout or an interrupt). Exit 124 on a timeout.
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

# The real home (kept for cargo and rustup, and for --real-applications).
real_home=$(cd "$HOME" && pwd -P)
export CARGO_HOME=${CARGO_HOME:-$real_home/.cargo}
export RUSTUP_HOME=${RUSTUP_HOME:-$real_home/.rustup}

root=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-usercheck.XXXXXX")
root=$(cd "$root" && pwd -P)
case $root in
  / | "") die "bad root" ;;
esac
mkdir -p "$root/build" "$root/work" "$root/pub" "$root/cli-home" "$root/mnt" "$root/release"

if [ "$real_apps" -eq 1 ]; then
  home=$real_home
else
  home=$root/home
  mkdir -p "$home"
fi
data_dir=$home/Library/Application\ Support/$app_id
bundle=$home/Applications/$app_name.app
out_file=$root/outcome.txt
report=$root/report.txt
: >"$out_file"
: >"$report"
server_pid=
installed_for_real=0

# Everything printed into the report passes here: control characters out, the root named, long
# lines cut.
clean() {
  LC_ALL=C tr -cd '[:print:]\n' | sed -e "s|$root|<root>|g" -e 's|^\(.\{200\}\).*|\1...|'
}
note() {
  printf '%s\n' "$*" | clean >>"$report"
}

stage_unregister() {
  [ -x "$lsregister" ] || return 0
  limited 30 "$lsregister" -u "$1" >/dev/null 2>&1 || true
}

cleanup() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ -s "$report" ]; then
    echo "macos-user-check: stopped early; the report so far:"
    cat "$report"
  fi
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  # What still runs from under the root (the app, the runtime, the UI): stopped.
  ps -axo pid=,args= 2>/dev/null | awk -v root="$root/" -v me="$$" '
    $1 != me && index($0, root) > 0 && index($0, " -v root=") == 0 { print $1 }
  ' | while IFS= read -r pid; do
    [ "$pid" = "$$" ] || kill "$pid" 2>/dev/null || true
  done
  # A real-home install that the walk did not finish: uninstalled by its own runtime, only when
  # this run installed it.
  if [ "$installed_for_real" -eq 1 ] && [ -x "$bundle/Contents/MacOS/lunepack-runtime" ]; then
    echo "macos-user-check: removing the app this run installed in the real home"
    limited 300 env -i "PATH=$PATH" "HOME=$real_home" "$bundle/Contents/MacOS/lunepack-runtime" uninstall --silent >/dev/null 2>&1 || true
    stage_unregister "$bundle"
  fi
  if [ "$real_apps" -eq 1 ]; then
    stage_unregister "$bundle"
    if [ "$installed_for_real" -eq 1 ] && { [ -e "$bundle" ] || [ -e "$data_dir" ]; }; then
      echo "macos-user-check: WARNING: this run's install is still in your real home; remove by hand:" >&2
      echo "  $bundle" >&2
      echo "  $data_dir" >&2
    fi
  fi
  # Detach what is mounted under the root.
  mount | while IFS= read -r line; do
    point=${line#* on }
    point=${point%% (*}
    case $point in
      "$root"/*) limited 60 hdiutil detach -force "$point" >/dev/null 2>&1 || true ;;
    esac
  done
  # Unregister every bundle LaunchServices may have seen under the root, then count again.
  if [ -x "$lsregister" ]; then
    find "$root" -name '*.app' -type d -prune 2>/dev/null | while IFS= read -r app; do
      stage_unregister "$app"
    done
    limited 120 "$lsregister" -dump 2>/dev/null | grep -E "^path:[[:space:]]+$root/" |
      sed -e 's/^path:[[:space:]]*//' -e 's/ (0x[0-9a-f]*)$//' | sort -u |
      while IFS= read -r known; do
        stage_unregister "$known"
      done || true
    left=$(limited 120 "$lsregister" -dump 2>/dev/null | grep "$root" | grep -c '\.app' || true)
    if [ "${left:-0}" -ne 0 ]; then
      echo "macos-user-check: WARNING: lsregister -dump still lists $left bundle lines under the root" >&2
    else
      echo "macos-user-check: lsregister lists no bundle under the root"
    fi
  else
    echo "macos-user-check: lsregister is absent: LaunchServices registrations were not checked"
  fi
  rm -rf "$root"
  exit "$status"
}
trap cleanup EXIT

if [ "$real_apps" -eq 1 ]; then
  if [ -e "$bundle" ] || [ -e "$data_dir" ]; then
    die "refusing: $app_name.app or its data folder ($app_id) already exists in the real home; nothing was touched"
  fi
  echo "This run installs and removes '$app_name' in your real Applications folder and in"
  echo "its Application Support folder ($app_id). It never touches anything else."
  printf 'Type yes to go on: '
  IFS= read -r answer || die "input closed"
  [ "$answer" = yes ] || die "not confirmed; nothing was touched"
fi

# ---- build ---------------------------------------------------------------------------------

tdir=${CARGO_TARGET_DIR:-$top/target}
echo "macos-user-check: building the runtime for $target"
limited 3600 ./scripts/build-runtime.sh "$target" --out "$root/build/lunepack-runtime"
echo "macos-user-check: building the command line, the example app and the real lunepack-ui"
limited 3600 cargo build --locked --release -p lunepack-cli
limited 3600 cargo build --locked --release -p lunepack --example e2e_app
limited 3600 cargo build --locked --release -p lunepack-ui
cli=$tdir/release/lunepack
for f in "$cli" "$tdir/release/examples/e2e_app" "$tdir/release/lunepack-ui"; do
  [ -f "$f" ] || die "the build left no $f"
done
cp "$tdir/release/examples/e2e_app" "$root/build/e2e_app"
cp "$tdir/release/lunepack-ui" "$root/build/lunepack-ui"
runtime_bin=$root/build/lunepack-runtime
ui_bin=$root/build/lunepack-ui

# The command line, with an empty environment but PATH and its own HOME.
cli_run() {
  (cd "$root/work" && limited 600 env -i "PATH=$PATH" "HOME=$root/cli-home" "$cli" "$@")
}

# ---- the feed ------------------------------------------------------------------------------

rd=$root/release
/usr/bin/python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$rd" >"$root/server.log" 2>&1 &
server_pid=$!
port=
i=0
while [ "$i" -lt 100 ] && [ -z "$port" ]; do
  port=$(sed -n 's/^Serving HTTP on 127\.0\.0\.1 port \([0-9][0-9]*\).*/\1/p' "$root/server.log" | head -n 1)
  [ -n "$port" ] || sleep 0.1
  i=$((i + 1))
done
[ -n "$port" ] || die "the feed server did not start"
feed=http://127.0.0.1:$port/
echo "macos-user-check: the feed is $feed"

# ---- the publisher -------------------------------------------------------------------------

pub=$root/pub
public_of() { # <key name>
  cli_run keys gen "$pub/$1.key" | sed -n 's/^public: //p' | head -n 1 | tr -d '[:space:]'
}
root_pub=$(public_of root)
release_pub=$(public_of release)
[ -n "$root_pub" ] && [ -n "$release_pub" ] || die "keys gen printed no public key"
cfg=$pub/lunepack.toml
cli_run init --app-id "$app_id" --root-key "$root_pub" --config "$cfg" >/dev/null
cat >"$cfg" <<EOF
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
feed = "$feed"
channel = "stable"
health_timeout_secs = 20

[install]
entry = "Contents/MacOS/$entry"
name = "$app_name"
comment = "The lunepack user check app"
EOF
cli_run keys set --release-dir "$rd" --release-key "$release_pub" --sign root --config "$cfg" >/dev/null

sign_adhoc() {
  limited 120 /usr/bin/codesign --force --sign - --timestamp=none "$1" >/dev/null 2>&1 ||
    die "codesign failed for ${1#"$root"/}"
}

# publish <version> <hold seconds or empty>: packs the signed bundle of that version into the
# release directory (not into the feed yet).
publish() {
  local ver=$1 hold=$2 input asm helper
  input=$root/work/in-$ver
  asm=$root/work/assembled-$ver
  mkdir -p "$input/Contents/MacOS" "$input/Contents/Resources"
  cat >"$input/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$entry</string>
<key>CFBundleIdentifier</key><string>org.lunepack.usercheck.app</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>$app_name</string>
<key>CFBundleShortVersionString</key><string>$ver</string>
</dict></plist>
EOF
  cp "$root/build/e2e_app" "$input/Contents/MacOS/$entry"
  chmod 755 "$input/Contents/MacOS/$entry"
  printf '%s\n' "$ver" >"$input/Contents/Resources/version.txt"
  if [ -n "$hold" ]; then
    # The started app stays alive that long, so the Dock and the focus can be looked at.
    printf 'hold %s\n' "$hold" >"$input/Contents/Resources/e2e-flags"
  fi
  cli_run pack --input "$input" --version "$ver" --target "$target" --runtime "$runtime_bin" \
    --ui "$ui_bin" --config "$cfg" --assemble "$asm" >/dev/null
  helper=$asm/Contents/Helpers/lunepack-update.app
  for code in "$asm/Contents/MacOS/lunepack-runtime" "$helper/Contents/MacOS/lunepack-ui" "$helper" "$asm"; do
    sign_adhoc "$code"
  done
  cli_run pack --input "$asm" --version "$ver" --target "$target" \
    --runtime "$asm/Contents/MacOS/lunepack-runtime" --ui "$helper/Contents/MacOS/lunepack-ui" \
    --config "$cfg" --release-dir "$rd" --sign release >/dev/null
}

feed_add() { # <version>
  cli_run feed add --release-dir "$rd" --channel stable --version "$1" --sign release --config "$cfg" >/dev/null
}

echo "macos-user-check: packing 1.0.0, 1.1.0 and 1.2.0 (ad-hoc signed)"
publish 1.0.0 ""
feed_add 1.0.0
publish 1.1.0 15
publish 1.2.0 15

dmg=$root/work/$app_id-1.0.0.dmg
zip=$root/work/$app_id-1.0.0.zip
cli_run setup "$rd" --version 1.0.0 --target "$target" --out "$dmg" --config "$cfg" >/dev/null
cli_run setup "$rd" --version 1.0.0 --target "$target" --zip --out "$zip" --config "$cfg" >/dev/null
[ -s "$dmg" ] && [ -s "$zip" ] || die "setup left no .dmg or .zip"

# The feed answers: its first document is served.
first=$(cd "$rd" && find . -maxdepth 2 -type f | sed 's|^\./||' | sort | head -n 1)
[ -n "$first" ] || die "the release directory is empty"
limited 20 /usr/bin/curl -fsS -o /dev/null "${feed}${first}" || die "the feed server does not serve ${first}"
echo "macos-user-check: built and serving; the .dmg and the .zip are ready"

# ---- helpers of the walk ---------------------------------------------------------------------

# The environment of every lunepack process of the walk: empty but PATH, the walk's home and the
# outcome file the example app writes.
walk_env=(env -i "PATH=$PATH" "HOME=$home" "LUNEPACK_E2E_OUT=$out_file")

attach_dmg() { # <mount point>
  mkdir -p "$1"
  limited 120 /usr/bin/hdiutil attach -nobrowse -noverify -noautoopen -readonly -mountpoint "$1" "$dmg" >/dev/null 2>&1 ||
    die "hdiutil attach failed"
}

detach_dmg() { # <mount point>
  limited 120 /usr/bin/hdiutil detach "$1" >/dev/null 2>&1 ||
    limited 120 /usr/bin/hdiutil detach -force "$1" >/dev/null 2>&1 || true
}

# wait_for <seconds> <what> <command...>: polls once a second.
wait_for() {
  local secs=$1 what=$2 i=0
  shift 2
  while ! "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -le "$secs" ] || die "timed out waiting for $what"
    sleep 1
  done
}

bundle_version() {
  [ "$(tr -d '[:space:]' <"$bundle/Contents/Resources/version.txt" 2>/dev/null)" = "$1" ]
}
# True when nothing runs from the installed bundle (the example app ends by itself).
app_not_running() {
  ! pgrep -f -- "$bundle/Contents/" >/dev/null 2>&1
}
outcome_has() {
  grep -qx "$1" "$out_file"
}

# ---- the headless pass -----------------------------------------------------------------------

if [ "$no_gui" -eq 1 ]; then
  echo "macos-user-check: --no-gui: install, check and uninstall without a window"
  mnt=$root/mnt/smoke
  attach_dmg "$mnt"
  installer=$mnt/Install\ "$app_name".app
  [ -x "$installer/Contents/MacOS/lunepack-ui" ] || die "the installer app has no lunepack-ui as its main executable"
  [ -x "$installer/Contents/MacOS/lunepack-runtime" ] || die "the installer app has no runtime"
  code=0
  limited 300 "${walk_env[@]}" "$installer/Contents/MacOS/lunepack-runtime" --silent >/dev/null 2>&1 || code=$?
  detach_dmg "$mnt"
  [ "$code" -eq 0 ] || die "the silent install exited $code"
  bundle_version 1.0.0 || die "the install left no 1.0.0 bundle"
  [ -L "$data_dir/bundle" ] || die "the install left no pointer"
  limited 120 /usr/bin/codesign --verify --deep --strict "$bundle" || die "the installed bundle does not verify"
  quarantined=$(limited 60 /usr/bin/xattr -lr "$bundle" 2>/dev/null | grep -c 'com.apple.quarantine' || true)
  [ "${quarantined:-0}" -eq 0 ] || die "the installed bundle carries a quarantine attribute"
  code=0
  limited 120 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" check --json >"$root/check.json" 2>/dev/null || code=$?
  [ "$code" -eq 0 ] || die "check --json exited $code"
  code=0
  limited 300 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" uninstall --silent >/dev/null 2>&1 || code=$?
  [ "$code" -eq 0 ] || die "the silent uninstall exited $code"
  [ ! -e "$bundle" ] && [ ! -e "$data_dir" ] || die "the uninstall left the bundle or the data folder"
  echo "macos-user-check: dry run PASS"
  exit 0
fi

# ---- the walk --------------------------------------------------------------------------------

ask_yn() { # <key> <question> <expected, or ->
  local answer
  while :; do
    printf '  %s [y/n]: ' "$2"
    IFS= read -r answer || die "input closed"
    case $answer in
      y | Y | yes) answer=y; break ;;
      n | N | no) answer=n; break ;;
    esac
  done
  note "$1: $answer (expected: $3)"
  printf '%s' "$answer" >"$root/last-answer"
}

ask_text() { # <key> <question>
  local answer
  printf '  %s (Enter to skip): ' "$2"
  IFS= read -r answer || die "input closed"
  if [ -n "$answer" ]; then
    note "$1 (note): $answer"
  fi
}

# prompts <stage key>: the question every stage asks.
prompts() {
  ask_yn "$1 prompt" "Did any Gatekeeper, App Management, \"background item\" or other system prompt appear?" "n"
  if [ "$(cat "$root/last-answer")" = y ]; then
    ask_text "$1 prompt" "Which one, and what did it say?"
  fi
}

pause() {
  printf '  %s ' "$1"
  IFS= read -r _ || die "input closed"
}

open_app() { # <flags...> -- <app> [args...]
  limited 60 /usr/bin/open --env "HOME=$home" --env "LUNEPACK_E2E_OUT=$out_file" "$@"
}

{
  echo "lunepack user check, $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "macOS $(sw_vers -productVersion 2>/dev/null || echo unknown), $(uname -m), commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if [ "$real_apps" -eq 1 ]; then echo "mode: real ~/Applications"; else echo "mode: temporary home"; fi
  echo
} | clean >>"$report"

echo
if [ "$real_apps" -eq 1 ]; then
  echo "The walk takes about 15 minutes. It uses your real home, as you asked."
else
  echo "The walk takes about 15 minutes. Everything happens in a temporary home under the system temp folder."
fi
echo

echo "Stage A: the installer"
mnt=$root/mnt/install
attach_dmg "$mnt"
installer=$mnt/Install\ "$app_name".app
echo "  The installer app is opened through LaunchServices now. Look at the Dock (the name),"
echo "  click Install in its window, and wait for it to say it is done."
pause "Press Enter to open it:"
open_app -n "$installer" || die "open failed for the installer"
if [ "$real_apps" -eq 1 ]; then installed_for_real=1; fi
wait_for 300 "the install to finish" bundle_version 1.0.0
sleep 3
pause "Press Enter when the installer window says it is done (or has closed):"
ask_yn "A installer dock name" "Did the Dock show the installer under the right name (\"$app_name\" or \"Install $app_name\")?" "y"
prompts "A"
ask_text "A" "Anything else you noticed?"
detach_dmg "$mnt"
note "A: installed 1.0.0: yes, pointer: $([ -L "$data_dir/bundle" ] && echo yes || echo no)"
verdict=$(limited 120 /usr/bin/codesign --verify --deep --strict "$bundle" >/dev/null 2>&1 && echo ok || echo failed)
quarantined=$(limited 60 /usr/bin/xattr -lr "$bundle" 2>/dev/null | grep -c 'com.apple.quarantine' || true)
note "A: instrument codesign --verify: $verdict; quarantine attributes under B: ${quarantined:-0}"
if [ -x /usr/sbin/spctl ]; then
  code=0
  limited 60 /usr/sbin/spctl --assess --type execute "$bundle" >/dev/null 2>&1 || code=$?
  note "A: instrument spctl --assess: exit $code (an ad-hoc app is expected to be rejected)"
fi
echo

echo "Stage B: start the installed app"
pause "Press Enter to start it:"
: >"$out_file"
open_app -n "$bundle" || die "open failed for the app"
wait_for 90 "the app to start" outcome_has "1.0.0 start"
prompts "B"
echo

# focus_stage <key> <version> <flag args> <expected focus answer>
update_stage() {
  local key=$1 ver=$2 expected=$3 flag=$4
  : >"$out_file"
  echo "  The app is started in the background and updates itself to $ver. First click on"
  echo "  another app (Finder, a browser) so that it is in front. You see the update window,"
  echo "  then the new version starts again (the whole update takes up to a minute; the old version"
  echo "  waits about 15 seconds first). Stay out of the way until the new version has started."
  pause "Press Enter, then click on another app within 5 seconds:"
  sleep 5
  if [ -n "$flag" ]; then
    open_app -g -n "$bundle" --args --update "$flag" || die "open failed for the update"
  else
    open_app -g -n "$bundle" --args --update || die "open failed for the update"
  fi
  wait_for 240 "the update to $ver" bundle_version "$ver"
  wait_for 90 "$ver to start again" outcome_has "$ver start"
  sleep 3
  note "$key: updated to $ver, version file: $ver"
  ask_yn "$key focus" "Did the relaunched app come to the front (take focus) while another app was in front?" "$expected"
  ask_yn "$key update window" "Did an update window appear, with the right name in the Dock?" "y"
  prompts "$key"
  ask_text "$key" "Anything else you noticed?"
  verdict=$(limited 120 /usr/bin/codesign --verify --deep --strict "$bundle" >/dev/null 2>&1 && echo ok || echo failed)
  note "$key: instrument codesign --verify: $verdict"
}

echo "Stage C: update to 1.1.0, plain apply-and-restart"
feed_add 1.1.0
update_stage "C" 1.1.0 "may" ""
echo

echo "Stage D: update to 1.2.0, apply-and-restart --background"
feed_add 1.2.0
update_stage "D" 1.2.0 "n" "--background"
echo

echo "Stage E: uninstall with the window"
echo "  The uninstall window opens. Confirm it."
wait_for 180 "the example app to end (it holds for a few seconds)" app_not_running
pause "Press Enter to start the uninstall:"
code=0
limited 300 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" uninstall >/dev/null 2>&1 || code=$?
installed_for_real=0
if [ -e "$bundle" ] || [ -e "$data_dir" ]; then
  note "E: uninstall exit $code; the bundle or the data folder is still there"
else
  note "E: uninstall exit $code; the bundle and the data folder are gone"
fi
prompts "E"
echo

echo "Stage F: a bundle taken out of the .zip"
echo "  The script extracts the .zip into the home's Applications folder (as dragging it out of"
echo "  the archive would), then you start the app. It is not installed: the check adopts it."
wait_for 60 "the uninstall to leave nothing behind" test ! -e "$bundle"
pause "Press Enter to extract it and start the app:"
mkdir -p "$home/Applications"
limited 120 /usr/bin/ditto -x -k "$zip" "$home/Applications" || die "ditto failed"
: >"$out_file"
open_app -n "$bundle" || die "open failed for the extracted app"
wait_for 90 "the extracted app to start" outcome_has "1.0.0 start"
prompts "F"
code=0
limited 180 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" check --json >"$root/check-adopt.json" 2>/dev/null || code=$?
if grep -q '"adopted":true' "$root/check-adopt.json" 2>/dev/null; then
  note "F: check --json exit $code, adopted: true"
else
  note "F: check --json exit $code, adopted: no"
fi
if [ "$real_apps" -eq 1 ]; then installed_for_real=1; fi
code=0
limited 300 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" uninstall --silent >/dev/null 2>&1 || code=$?
if [ "$code" -eq 0 ]; then installed_for_real=0; fi
note "F: cleanup uninstall --silent exit $code"
echo

echo "The report:"
echo "-----------"
cat "$report"
echo "-----------"
echo "macos-user-check: done. Copy the report from above; the temporary root is removed now."
