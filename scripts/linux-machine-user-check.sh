#!/usr/bin/env bash
# The user-run check of the Linux per-machine install (M11 step 14, M11-D9; roadmap P4). The suite
# (scripts/e2e-linux-machine.sh) answers pkexec with a polkit rule; only a person at a desktop sees
# the real authentication agent's prompt, the window's "For all users" choice, the desktop entry in
# the launcher. A person at a Linux desktop walks the real flow once and answers a few questions;
# the answers go to a report. About 10 minutes. It is never part of the gate or CI.
#
#   scripts/linux-machine-user-check.sh --standard-user <name>
#   scripts/linux-machine-user-check.sh --dry-run          list the stages; every stage is SKIPPED
#
# Run it in a terminal of a graphical session on a DISPOSABLE machine (a test VM with
# exclusive use), as an account that may authenticate for pkexec and use `sudo`: it installs a test
# app for all users (/opt, units under /etc/systemd/system, /usr/local, /run/lunepack). The standard
# account named by `--standard-user` must already exist (a second account, not an administrator);
# the script creates and deletes no account and never asks for a password: the only places a
# password is typed are the pkexec agent's and `sudo`'s own prompts.
#
# What it does: builds the static runtime, the static update service (musl), `lunepack`, the example
# app and the real `lunepack-ui`, packs 1.0.0 and 1.1.0 with the service into
# /tmp/lunepack-linux-machine-check-<hex> (the standard account reads it), builds the setup file of
# 1.0.0, and then, with you in front of the screen:
#   A. the setup file, started by this script in your session: choose "For all users"; the real
#      polkit agent asks for the administrator's password; the install finishes;
#   B. what the system shows: the desktop entry in the launcher, the command link, the socket unit;
#   C. the standard account updates the app to 1.1.0 through the service (the script starts it with
#      `sudo -u`, which asks your password once): no prompt for that account is expected;
#   D. the uninstall: the app's own `uninstall` window, started by you in Terminal; the pkexec agent
#      asks again; nothing is left.
# At each stage it asks whether a prompt or notice appeared and what else you noticed. The answers,
# with the verdicts of read-only instruments (`stat`, `systemctl is-active`, `desktop-file-validate`),
# go to a report that is printed at the end. It holds no path outside /opt, /usr/local, /etc/systemd
# and the work folder, and no environment.
#
# The trap removes only the work folder, and only when the install is gone; if the walk stops early
# with the app installed it prints the one command that removes it. bash 4 is not needed (3.2).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: scripts/linux-machine-user-check.sh --standard-user <name>" >&2
  echo "       scripts/linux-machine-user-check.sh --dry-run" >&2
}

die() {
  echo "linux-machine-user-check: $*" >&2
  exit 1
}

STAGES=(
  "A  the setup file: For all users, the real pkexec agent's prompt, the install"
  "B  the desktop entry in the launcher, the command link, the socket unit (read only)"
  "C  the standard account updates the app to 1.1.0 through the service"
  "D  the uninstall from the app's window: the pkexec agent again; nothing left"
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
  echo "linux-machine-user-check: dry run: nothing is built, installed or asked"
  for stage in "${STAGES[@]}"; do
    echo "  SKIPPED  $stage"
  done
  echo "linux-machine-user-check: ${#STAGES[@]} stages listed, all SKIPPED"
  exit 0
fi

[ -n "$std" ] || {
  usage
  exit 2
}
[ "$(uname -s)" = Linux ] || die "refusing to run: Linux only (a person at a Linux desktop)"
if [ "$(id -u)" = 0 ]; then
  die "refusing to run as root: run it as your own account; pkexec asks for the password"
fi
if [ ! -t 0 ] || [ ! -t 1 ]; then
  die "refusing to run without a terminal: the walk asks questions"
fi
if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
  die "refusing to run without a graphical session (DISPLAY or WAYLAND_DISPLAY): the check is about what the desktop shows"
fi
id "$std" >/dev/null 2>&1 || die "refusing to run: the standard account '$std' does not exist"
if id -Gn "$std" | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; then
  die "refusing to run: '$std' may administer the machine; name a standard account"
fi
[ "$std" != "$(id -un)" ] || die "refusing to run: the standard account must not be this one"
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
for tool in /usr/bin/pkexec /usr/bin/sudo /usr/bin/systemctl; do
  [ -x "$tool" ] || die "refusing to run: $tool is missing"
done
for tool in cargo readelf; do
  command -v "$tool" >/dev/null 2>&1 || die "refusing to run: $tool is not installed (the build needs it)"
done

app_id=org.lunepack.machinecheck
app_name="Lunepack Machine Check"
bin=lunepack-machine-check
R=/opt/$app_id
sock=/run/lunepack/$app_id.sock
units=/etc/systemd/system
for p in "$R" "$sock" "$units/lunepack-$app_id.socket" "$units/lunepack-$app_id.service" "/usr/local/bin/$bin" "/usr/local/share/applications/$app_id.desktop"; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    die "refusing: $p already exists; nothing was touched"
  fi
done

hexid=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
root=/tmp/lunepack-linux-machine-check-$hexid
[ ! -e "$root" ] || die "refusing: $root exists"
mkdir -m 755 "$root"
mkdir -m 755 "$root/build" "$root/work" "$root/release" "$root/setup"
mkdir -m 700 "$root/pub" "$root/cli-home"
report=$root/report.txt
: >"$report"
outfile=$root/outcome.txt
: >"$outfile"
chmod 666 "$outfile"

clean() { LC_ALL=C tr -cd '[:print:]\n' | sed -e "s|$root|<work>|g" -e 's|^\(.\{200\}\).*|\1...|'; }
note() { printf '%s\n' "$*" | clean >>"$report"; }

cleanup() {
  local status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ -s "$report" ]; then
    echo "linux-machine-user-check: stopped early; the report so far:"
    cat "$report"
  fi
  if [ -e "$R" ] || [ -e "$units/lunepack-$app_id.socket" ]; then
    echo "linux-machine-user-check: the app is still installed; the work folder stays." >&2
    echo "  To remove it:  sudo '$R/current/bin/lunepack-runtime' uninstall" >&2
    echo "  then:          rm -rf '$root'" >&2
  else
    rm -rf "$root"
  fi
  exit "$status"
}
trap cleanup EXIT

# ---- build and pack ---------------------------------------------------------------------------

tdir=${CARGO_TARGET_DIR:-$top/target}
echo "linux-machine-user-check: building for $target (this takes a while: the real UI is built too)"
./scripts/build-runtime.sh "$target" --out "$root/build/lunepack-runtime"
cargo build --locked --release -p lunepack-service --target "$triple" --config profile.release.strip=true
cargo build --locked --release -p lunepack-cli -p lunepack-ui
cargo build --locked --release -p lunepack --example e2e_app
cli=$tdir/release/lunepack
cp "$tdir/$triple/release/lunepack-service" "$root/build/lunepack-service"
cp "$tdir/release/lunepack-ui" "$root/build/lunepack-ui"
cp "$tdir/release/examples/e2e_app" "$root/build/e2e_app"
for f in "$cli" "$root/build/lunepack-runtime" "$root/build/lunepack-service" "$root/build/lunepack-ui" "$root/build/e2e_app"; do
  [ -f "$f" ] || die "the build left no ${f##*/}"
done
chmod -R a+rX "$root/build"

cli_run() { (cd "$root/work" && env -i "PATH=$PATH" "HOME=$root/cli-home" "$cli" "$@"); }
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
entry = "bin/$bin"
name = "$app_name"
comment = "The lunepack machine user check app"
categories = ["Utility"]
bin = "$bin"
terminal = false
EOF
cli_run keys set --release-dir "$rd" --release-key "$release_pub" --sign root --config "$cfg" >/dev/null

publish() { # VERSION
  local ver=$1 input=$root/work/in-$1
  mkdir -p "$input/bin" "$input/share"
  cp "$root/build/e2e_app" "$input/bin/$bin"
  chmod 755 "$input/bin/$bin"
  printf '%s\n' "$ver" >"$input/share/version.txt"
  cli_run pack --input "$input" --version "$ver" --target "$target" --release-dir "$rd" --sign release \
    --runtime "$root/build/lunepack-runtime" --service "$root/build/lunepack-service" \
    --ui "$root/build/lunepack-ui" --config "$cfg" >/dev/null
}
feed_add() { cli_run feed add --release-dir "$rd" --channel stable --version "$1" --sign release --config "$cfg" >/dev/null; }

echo "linux-machine-user-check: packing 1.0.0 and 1.1.0 (with the service and the real UI)"
publish 1.0.0
feed_add 1.0.0
publish 1.1.0
setup=$root/setup/$app_id-1.0.0-$target-setup
cli_run setup "$rd" --version 1.0.0 --target "$target" --out "$setup" --config "$cfg" >/dev/null
[ -x "$setup" ] || die "setup left no setup file"
chmod -R a+rX "$root"

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
  ask_yn "$1 prompt" "Did any prompt or notice appear that this stage did not name?" "n"
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
current_is() { [ "$(readlink "$R/current" 2>/dev/null)" = "app/$1" ]; }
facts() { stat -c 'owner=%U:%G mode=%a type=%F' "$1" 2>/dev/null || echo missing; }

{
  echo "lunepack linux machine user check, $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "$(uname -sr) $(uname -m), polkit/pkexec $(pkexec --version 2>/dev/null | head -n 1 | tr -cd '[:print:]'), commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo
} | clean >>"$report"

echo
echo "The walk takes about 10 minutes. It installs '$app_name' for all users on this machine."
echo

# ---- stage A ----------------------------------------------------------------------------------

echo "Stage A: the setup file"
echo "  The setup window opens in your session. Choose \"For all users\". The real authentication"
echo "  agent of your desktop asks for the administrator's password: read what it says about the"
echo "  program it runs, give the password, and let the install finish."
pause "Press Enter to start the setup file:"
setsid "$setup" >"$root/setup.out" 2>"$root/setup.err" </dev/null &
wait_for 600 "the install to finish" test -L "$R/current"
wait_for 120 "version 1.0.0" current_is 1.0.0
sleep 3
ask_yn "A all-users choice" "Did the setup window offer \"For all users\"?" "y"
ask_yn "A agent prompt" "Did your desktop's authentication agent ask for a password?" "y"
ask_yn "A agent text" "Did the agent's text name the setup file's path (it cannot name a publisher)?" "y"
ask_yn "A window" "Did the setup window show the progress and then say it was done?" "y"
prompts "A"
ask_text "A" "Anything else you noticed?"
note "A: installed 1.0.0: yes; instrument R: $(facts "$R")"
note "A: instrument machine folder: $(facts "$R/.lunepack/machine")"
note "A: instrument socket: $(facts "$sock")"
note "A: instrument socket unit active: $(systemctl is-active "lunepack-$app_id.socket" 2>/dev/null || true)"
echo

# ---- stage B ----------------------------------------------------------------------------------

echo "Stage B: what the system shows"
echo "  Open your launcher or application menu and search for \"$app_name\"."
ask_yn "B launcher" "Does the launcher list \"$app_name\" with an icon or a generic one?" "y"
ask_yn "B command" "In a NEW terminal, does the command \"$bin\" exist (type its name; it starts the app)?" "y"
ask_text "B" "Anything else you noticed (the entry's category, the icon)?"
note "B: instrument desktop entry validates: $(desktop-file-validate "/usr/local/share/applications/$app_id.desktop" >/dev/null 2>&1 && echo ok || echo 'failed or desktop-file-validate is missing')"
note "B: instrument command link: $(readlink "/usr/local/bin/$bin" 2>/dev/null | sed "s|$R|<R>|" || echo missing)"
echo

# ---- stage C ----------------------------------------------------------------------------------

echo "Stage C: the standard account updates the app"
feed_add 1.1.0
echo "  The script starts the app as '$std' with sudo (it asks for YOUR password once, at the sudo"
echo "  prompt of this terminal). The app finds 1.1.0, downloads it through the service and"
echo "  relaunches as 1.1.0. Expect NO prompt for '$std' of any kind."
pause "Press Enter to run the update as '$std':"
sudo -u "$std" env -i HOME="$(getent passwd "$std" | cut -d: -f6)" PATH=/usr/bin:/bin LUNEPACK_E2E_OUT="$outfile" \
  "$R/current/bin/$bin" --update --no-ui >/dev/null 2>&1 </dev/null || true
wait_for 300 "the update to 1.1.0" current_is 1.1.0
ask_yn "C prompt-free" "Did the update finish without any prompt (the script's sudo prompt excepted)?" "y"
prompts "C"
ask_text "C" "Anything else you noticed?"
note "C: updated to 1.1.0: yes; instrument R/current: $(readlink "$R/current" 2>/dev/null || echo missing)"
echo

# ---- stage D ----------------------------------------------------------------------------------

echo "Stage D: the uninstall"
echo "  In Terminal, as yourself, run exactly:"
echo
echo "    '$R/current/bin/lunepack-runtime' uninstall"
echo
echo "  An uninstall window opens: confirm it. Your authentication agent asks for the password"
echo "  once more; the window then says it is done."
pause "Press Enter when it has finished:"
leftover=""
for p in "$R" "$sock" "$units/lunepack-$app_id.socket" "$units/lunepack-$app_id.service" "/usr/local/bin/$bin" "/usr/local/share/applications/$app_id.desktop"; do
  if [ -e "$p" ] || [ -L "$p" ]; then leftover="$leftover ${p##*/}"; fi
done
if ls -d /opt/.lunepack-* >/dev/null 2>&1; then leftover="$leftover (a staging or uninstall folder)"; fi
if [ -z "$leftover" ]; then note "D: nothing left of the install"; else note "D: LEFT OVER:$leftover"; fi
ask_yn "D agent prompt" "Did the authentication agent ask for a password during the uninstall?" "y"
ask_yn "D window" "Did the uninstall window confirm that it was done?" "y"
ask_yn "D launcher" "Is the app gone from the launcher?" "y"
prompts "D"
ask_text "D" "Anything else you noticed?"
echo

echo "The report:"
echo "-----------"
cat "$report"
echo "-----------"
echo "linux-machine-user-check: done. Copy the report from above."
