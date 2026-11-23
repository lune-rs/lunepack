#!/usr/bin/env bash
# The user-run check of the macOS per-machine install (M11 step 14, M11-D1; roadmap P4). The suite
# (scripts/e2e-macos-machine.sh) cannot see what a person sees: Installer's own prompt, the
# "background item added" notice, the Login Items & Extensions entry, what a standard user is asked
# when an app updates itself. A person at a disposable Mac walks the real flow once and answers a
# few questions; the answers go to a report. About 15 minutes. It is never part of the gate or CI.
#
#   scripts/macos-machine-user-check.sh --standard-user <name>
#   scripts/macos-machine-user-check.sh --dry-run          list the stages; every stage is SKIPPED
#
# Run it as an ADMINISTRATOR (not through sudo) in a terminal on a DISPOSABLE Mac or macOS VM: it
# installs a test app for all users (/Applications, a LaunchDaemon, /Library/Application Support/
# lunepack), through Apple's Installer, which asks you for the administrator's password. The standard
# account named by `--standard-user` must already exist (a second account, not an administrator);
# the script creates and deletes no account and never asks for a password itself: the only places a
# password is typed are Installer's and `sudo`'s own prompts, in the commands it prints for you.
#
# What it does: builds the release runtime, the update service, `lunepack` and the example app,
# packs 1.0.0, 1.1.0 and 1.2.0 as ad-hoc signed bundles with the service into
# /Users/Shared/lunepack-machine-check-<hex> (the standard account reads it), builds the `.dmg` of
# 1.0.0 and opens it. Then, with you in front of the screen:
#   A. the installer app from the `.dmg`: choose "For all users"; the window should say to continue
#      in Installer; Installer asks for the administrator's password; the install finishes;
#   B. what the system showed: the notice for a background item, the entry under System Settings >
#      General > Login Items & Extensions (read only: `sfltool dumpbtm` when `sudo` is already
#      authorised, else your answer);
#   C. the standard account: log in as it (fast user switching), start the app from /Applications,
#      run the command the script prints, which updates to 1.1.0 through the service; no prompt is
#      expected; the new version starts;
#   D. back as the administrator: an update to 1.2.0 the same way while the app of 1.1.0 runs (the
#      bundle swap waits for it);
#   E. the uninstall: the script prints `sudo '<runtime>' uninstall`; you run it in Terminal.
# At each stage it asks whether a prompt or notice appeared (Gatekeeper, App Management, "background
# item", Installer's), whether the Dock showed the right name, and what else you noticed. The answers,
# with the exit codes and the verdicts of read-only instruments (`stat`, `pkgutil`, `codesign`), go to
# a report that is printed at the end. The report holds no path outside /Applications, /Library and
# the work folder, and no environment.
#
# The trap removes only the work folder, and only when the install is gone; it never removes what
# Installer made (the uninstall in stage E does, through the runtime). If the walk stops early with
# the app installed, it prints the one command that removes it. bash 3.2 compatible.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: scripts/macos-machine-user-check.sh --standard-user <name>" >&2
  echo "       scripts/macos-machine-user-check.sh --dry-run" >&2
}

die() {
  echo "macos-machine-user-check: $*" >&2
  exit 1
}

STAGES=(
  "A  the installer app from the .dmg: For all users, the hand-off to Installer, Installer's prompt"
  "B  the system's notice and the Login Items & Extensions entry (sfltool dumpbtm, read only)"
  "C  the standard account starts the app and updates it to 1.1.0 through the service"
  "D  the update to 1.2.0 while the app runs (the swap waits), as the administrator"
  "E  the uninstall: sudo '<runtime>' uninstall; nothing left"
)

dry=0
std=
while [ "$#" -gt 0 ]; do
  case $1 in
    --dry-run)
      dry=1
      shift
      ;;
    --standard-user)
      [ "$#" -ge 2 ] && [ -n "$2" ] || {
        usage
        exit 2
      }
      std=$2
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

if [ "$dry" -eq 1 ]; then
  [ -z "$std" ] || {
    usage
    exit 2
  }
  echo "macos-machine-user-check: dry run: nothing is built, installed or asked"
  for stage in "${STAGES[@]}"; do
    echo "  SKIPPED  $stage"
  done
  echo "macos-machine-user-check: ${#STAGES[@]} stages listed, all SKIPPED"
  exit 0
fi

[ -n "$std" ] || {
  usage
  exit 2
}
[ "$(uname -s)" = Darwin ] || die "refusing to run: macOS only (a person at a Mac walks Installer)"
if [ "$(id -u)" = 0 ]; then
  die "refusing to run as root: run it as an administrator; Installer asks for the password"
fi
if [ ! -t 0 ] || [ ! -t 1 ]; then
  die "refusing to run without a terminal: the walk asks questions"
fi
id -Gn | tr ' ' '\n' | grep -qx admin || die "refusing to run: this account is not an administrator"
id "$std" >/dev/null 2>&1 || die "refusing to run: the standard account '$std' does not exist"
if id -Gn "$std" | tr ' ' '\n' | grep -qx admin; then
  die "refusing to run: '$std' is an administrator; name a standard account"
fi
[ "$std" != "$(id -un)" ] || die "refusing to run: the standard account must not be this one"
case $(uname -m) in
  arm64) target=macos-aarch64 ;;
  x86_64) target=macos-x86_64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
for tool in /usr/bin/hdiutil /usr/bin/codesign /usr/bin/open /usr/bin/python3 /usr/bin/perl /usr/bin/pkgutil; do
  [ -x "$tool" ] || die "$tool is missing"
done

app_id=org.lunepack.machinecheck
app_name="Lunepack Machine Check"
entry=lunepack-machine-check
label=lunepack-$app_id
home_dir="/Library/Application Support/lunepack"
R="$home_dir/$app_id"
B="/Applications/$app_name.app"
plist=/Library/LaunchDaemons/$label.plist
for p in "$R" "$B" "$plist"; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    die "refusing: $p already exists; nothing was touched"
  fi
done

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

hexid=$(/usr/bin/python3 -c 'import secrets; print(secrets.token_hex(4))')
root=/Users/Shared/lunepack-machine-check-$hexid
[ ! -e "$root" ] || die "refusing: $root exists"
mkdir -m 755 "$root"
mkdir -m 755 "$root/build" "$root/work" "$root/release" "$root/setup"
mkdir -m 700 "$root/pub" "$root/cli-home"
report=$root/report.txt
: >"$report"
real_home=$(cd "$HOME" && pwd -P)
export CARGO_HOME=${CARGO_HOME:-$real_home/.cargo}
export RUSTUP_HOME=${RUSTUP_HOME:-$real_home/.rustup}

clean() { LC_ALL=C tr -cd '[:print:]\n' | sed -e "s|$root|<work>|g" -e 's|^\(.\{200\}\).*|\1...|'; }
note() { printf '%s\n' "$*" | clean >>"$report"; }

cleanup() {
  local status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ -s "$report" ]; then
    echo "macos-machine-user-check: stopped early; the report so far:"
    cat "$report"
  fi
  if [ -e "$B" ] || [ -e "$R" ] || [ -e "$plist" ]; then
    echo "macos-machine-user-check: the app is still installed; the work folder stays." >&2
    echo "  To remove it:  sudo '$B/Contents/MacOS/lunepack-runtime' uninstall" >&2
    echo "  then:          rm -rf '$root'" >&2
  else
    rm -rf "$root"
  fi
  exit "$status"
}
trap cleanup EXIT

# ---- build and pack ---------------------------------------------------------------------------

tdir=${CARGO_TARGET_DIR:-$top/target}
echo "macos-machine-user-check: building for $target"
limited 3600 ./scripts/build-runtime.sh "$target" --out "$root/build/lunepack-runtime"
limited 3600 cargo build --locked --release -p lunepack-cli -p lunepack-service
limited 3600 cargo build --locked --release -p lunepack --example e2e_app
cli=$tdir/release/lunepack
cp "$tdir/release/lunepack-service" "$root/build/lunepack-service"
cp "$tdir/release/examples/e2e_app" "$root/build/e2e_app"
for f in "$cli" "$root/build/lunepack-runtime" "$root/build/lunepack-service" "$root/build/e2e_app"; do
  [ -f "$f" ] || die "the build left no ${f##*/}"
done
chmod -R a+rX "$root/build"

cli_run() { (cd "$root/work" && limited 600 env -i "PATH=$PATH" "HOME=$root/cli-home" "$cli" "$@"); }
rd=$root/release
cfg=$root/pub/lunepack.toml
public_of() { cli_run keys gen "$root/pub/$1.key" | sed -n 's/^public: //p' | head -n 1 | tr -d '[:space:]'; }
root_pub=$(public_of root)
release_pub=$(public_of release)
[ -n "$root_pub" ] && [ -n "$release_pub" ] || die "keys gen printed no public key"
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
feed = "file://$rd/"
channel = "stable"
health_timeout_secs = 30

[install]
entry = "Contents/MacOS/$entry"
name = "$app_name"
comment = "The lunepack machine user check app"
EOF
cli_run keys set --release-dir "$rd" --release-key "$release_pub" --sign root --config "$cfg" >/dev/null

sign_adhoc() { limited 120 /usr/bin/codesign --force --sign - --timestamp=none "$1" >/dev/null 2>&1 || die "codesign failed for ${1#"$root"/}"; }

publish() { # VERSION HOLD-SECONDS-OR-EMPTY
  local ver=$1 hold=$2 input asm code
  input=$root/work/in-$ver
  asm=$root/work/assembled-$ver
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
  if [ -n "$hold" ]; then
    printf 'hold %s\n' "$hold" >"$input/Contents/Resources/e2e-flags"
  fi
  cli_run pack --input "$input" --version "$ver" --target "$target" --runtime "$root/build/lunepack-runtime" \
    --service "$root/build/lunepack-service" --config "$cfg" --assemble "$asm" >/dev/null
  for code in "$asm/Contents/MacOS/lunepack-runtime" "$asm/Contents/MacOS/lunepack-service" "$asm"; do
    sign_adhoc "$code"
  done
  cli_run pack --input "$asm" --version "$ver" --target "$target" \
    --runtime "$asm/Contents/MacOS/lunepack-runtime" --service "$asm/Contents/MacOS/lunepack-service" \
    --config "$cfg" --release-dir "$rd" --sign release >/dev/null
}
feed_add() { cli_run feed add --release-dir "$rd" --channel stable --version "$1" --sign release --config "$cfg" >/dev/null; }

echo "macos-machine-user-check: packing 1.0.0, 1.1.0 and 1.2.0 (ad-hoc signed, with the service)"
publish 1.0.0 ""
feed_add 1.0.0
publish 1.1.0 45
publish 1.2.0 15
dmg=$root/setup/$app_id-1.0.0.dmg
cli_run setup "$rd" --version 1.0.0 --target "$target" --out "$dmg" --config "$cfg" >/dev/null
[ -s "$dmg" ] && [ -s "${dmg%.dmg}.pkg" ] || die "setup left no .dmg and .pkg"
chmod -R a+rX "$root"
rt=$B/Contents/MacOS/lunepack-runtime
outfile=$root/outcome.txt
: >"$outfile"
chmod 666 "$outfile"

# ---- helpers of the walk ----------------------------------------------------------------------

ask_yn() { # KEY QUESTION EXPECTED
  local answer
  while :; do
    printf '  %s [y/n]: ' "$2"
    IFS= read -r answer || die "input closed"
    case $answer in
      y | Y | yes)
        answer=y
        break
        ;;
      n | N | no)
        answer=n
        break
        ;;
    esac
  done
  note "$1: $answer (expected: $3)"
  printf '%s' "$answer" >"$root/last-answer"
}
ask_text() { # KEY QUESTION
  local answer
  printf '  %s (Enter to skip): ' "$2"
  IFS= read -r answer || die "input closed"
  if [ -n "$answer" ]; then note "$1 (note): $answer"; fi
}
prompts() {
  ask_yn "$1 prompt" "Did any Gatekeeper, App Management, Installer, \"background item\" or other system prompt or notice appear?" "installer: y; others: see the stage"
  if [ "$(cat "$root/last-answer")" = y ]; then ask_text "$1 prompt" "Which one, and what did it say?"; fi
}
pause() {
  printf '  %s ' "$1"
  IFS= read -r _ || die "input closed"
}
wait_for() { # SECONDS WHAT COMMAND...
  local secs=$1 what=$2 i=0
  shift 2
  while ! "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -le "$secs" ] || die "timed out waiting for $what"
    sleep 1
  done
}
bundle_is() { [ "$(tr -d '[:space:]' <"$B/Contents/Resources/version.txt" 2>/dev/null)" = "$1" ]; }
outcome_has() { grep -qx "$1" "$outfile"; }
facts() { # read-only: owner, mode and type of a path
  stat -f 'owner=%Su:%Sg mode=%Lp type=%HT' "$1" 2>/dev/null || echo missing
}

{
  echo "lunepack machine user check, $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "macOS $(sw_vers -productVersion 2>/dev/null || echo unknown), $(uname -m), commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo
} | clean >>"$report"

echo
echo "The walk takes about 15 minutes. It installs '$app_name' for all users on this Mac."
echo

# ---- stage A ----------------------------------------------------------------------------------

echo "Stage A: the installer"
mnt=$root/mnt
mkdir -p "$mnt"
limited 120 /usr/bin/hdiutil attach -nobrowse -noverify -noautoopen -readonly -mountpoint "$mnt" "$dmg" >/dev/null 2>&1 || die "hdiutil attach failed"
echo "  The installer app opens now. In its window choose \"For all users\". The window should say"
echo "  to continue in Installer; Installer then asks for the administrator's password. Give it,"
echo "  and let Installer finish."
pause "Press Enter to open the installer app:"
limited 60 /usr/bin/open -n "$mnt/Install $app_name.app" || die "open failed for the installer"
wait_for 600 "the install to finish" test -d "$B"
wait_for 120 "the app's version file" bundle_is 1.0.0
sleep 3
limited 120 /usr/bin/hdiutil detach "$mnt" >/dev/null 2>&1 || limited 120 /usr/bin/hdiutil detach -force "$mnt" >/dev/null 2>&1 || true
ask_yn "A all-users choice" "Did the installer window offer \"For all users\", and say to continue in Installer after you chose it?" "y"
ask_yn "A installer prompt" "Did Installer ask for the administrator's password (or Touch ID)?" "y"
ask_yn "A dock name" "Did the Dock show the installer under the right name?" "y"
prompts "A"
ask_text "A" "Anything else you noticed?"
note "A: installed 1.0.0: yes"
note "A: instrument bundle: $(facts "$B")"
note "A: instrument install root: $(facts "$R")"
note "A: instrument daemon plist: $(facts "$plist")"
note "A: instrument codesign --verify: $(limited 120 /usr/bin/codesign --verify --deep --strict "$B" >/dev/null 2>&1 && echo ok || echo failed)"
note "A: instrument pkgutil --pkgs: $(pkgutil --pkgs 2>/dev/null | grep -c "$app_id" || true) receipt(s) for the app"
echo

# ---- stage B ----------------------------------------------------------------------------------

echo "Stage B: what the system showed"
echo "  Open System Settings > General > Login Items & Extensions and look under \"Allow in the"
echo "  Background\" (and \"App Background Activity\")."
ask_yn "B notice" "Did macOS show a notice that a background item was added (when the install finished)?" "may"
ask_yn "B entry" "Is there an entry for the app or its daemon under Login Items & Extensions?" "may"
ask_yn "B toggle" "If there is one, is it switched on (allowed) without you having turned it on?" "y"
ask_text "B" "What is the entry called, and who is named as the developer?"
if sudo -n true 2>/dev/null && [ -x /usr/bin/sfltool ]; then
  note "B: instrument sfltool dumpbtm lists the label: $(limited 60 sudo -n /usr/bin/sfltool dumpbtm 2>/dev/null | grep -c "$label" || true) time(s)"
else
  note "B: instrument sfltool dumpbtm: not run (sudo is not authorised here)"
fi
echo

# ---- stage C ----------------------------------------------------------------------------------

echo "Stage C: the standard account updates the app"
feed_add 1.1.0
echo "  Log in as '$std' (fast user switching: the Apple menu or the menu bar's user menu). This"
echo "  script keeps running. As '$std', in Terminal, run exactly:"
echo
echo "    open -n -a '$B' --args --update --no-ui"
echo
echo "  (the app starts, finds 1.1.0, downloads it through the service and relaunches as 1.1.0)."
echo "  Expect NO password prompt for '$std'. Wait until the app of 1.1.0 has started."
wait_for 900 "the update to 1.1.0 (as $std)" bundle_is 1.1.0
sleep 3
ask_yn "C prompt-free" "Did '$std' get through the update without any password or approval prompt?" "y"
ask_yn "C relaunch" "Did the app of 1.1.0 start by itself after the update?" "y"
prompts "C"
ask_text "C" "Anything else you noticed (Dock name, windows, focus)?"
note "C: updated to 1.1.0: yes; instrument bundle: $(facts "$B")"
echo

# ---- stage D ----------------------------------------------------------------------------------

echo "Stage D: an update while the app runs"
feed_add 1.2.0
echo "  Log back in as the administrator. The app of 1.1.0 holds for about 45 seconds when it starts."
echo "  Start it, and while it runs update from a second Terminal; the swap waits for the app."
pause "Press Enter to start the app and update (it takes up to two minutes):"
: >"$outfile"
limited 60 /usr/bin/open -n "$B" --args --update --no-ui || die "open failed for the app"
wait_for 600 "the update to 1.2.0" bundle_is 1.2.0
wait_for 120 "1.2.0 to start" outcome_has "1.2.0 start"
ask_yn "D swap" "Did the app quit, and the new version start, without any prompt?" "y"
prompts "D"
note "D: updated to 1.2.0: yes; instrument codesign --verify: $(limited 120 /usr/bin/codesign --verify --deep --strict "$B" >/dev/null 2>&1 && echo ok || echo failed)"
echo

# ---- stage E ----------------------------------------------------------------------------------

echo "Stage E: the uninstall"
echo "  Quit the app. Then, in Terminal, run exactly (it asks for your password):"
echo
echo "    sudo '$rt' uninstall"
echo
pause "Press Enter when the command has finished:"
leftover=""
for p in "$B" "$R" "$plist" "/var/run/lunepack-$app_id.sock" "/Library/LaunchAgents/lunepack-$app_id.autostart.plist"; do
  if [ -e "$p" ] || [ -L "$p" ]; then leftover="$leftover ${p##*/}"; fi
done
if ls -d "$home_dir"/.lunepack-uninstall-* "$home_dir"/.lunepack-install-* >/dev/null 2>&1; then
  leftover="$leftover (a staging or uninstall folder)"
fi
if [ -z "$leftover" ]; then note "E: nothing left of the install"; else note "E: LEFT OVER:$leftover"; fi
ask_yn "E entry" "Is the Login Items & Extensions entry gone?" "y"
prompts "E"
ask_text "E" "Anything else you noticed?"
echo

echo "The report:"
echo "-----------"
cat "$report"
echo "-----------"
echo "macos-machine-user-check: done. Copy the report from above."
