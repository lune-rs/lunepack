#!/usr/bin/env bash
# The end-to-end suite of the macOS runtime (M8 step 10): installs an app from a `.dmg`, updates it
# by a bundle swap, rolls back what does not confirm, adopts a bundle dragged out of a `.zip`, and
# uninstalls it, all on this Mac with real processes. It is not part of the gate (scripts/gate.sh).
#
#   scripts/e2e-macos.sh [--ci]
#
# One `mktemp -d` root (canonical, `pwd -P`) holds everything: `HOME` is `<root>/home` for every
# lunepack process (the harness checks it and aborts otherwise), the build outputs and every disk
# image's mount point. Nothing is written outside the root except LaunchServices' own records of
# the bundles the rows start through `open`; the trap unregisters them with `lsregister -u`,
# detaches every image mounted under the root and removes the root. No sudo, no signing identity
# (ad-hoc only). Every external tool (`hdiutil`, `codesign`, `spctl`, `open`, ...) is bounded.
# `--ci` adds the rows that launch the installed bundle through LaunchServices (row 12).
#
# It builds the release `lunepack-runtime` (scripts/build-runtime.sh), `lunepack`, the Rust example
# app, the stand-in UI (tests/e2e/fake-ui), then runs the test binary crates/lunepack-runtime/tests/e2e
# with them and with the shell app (tests/e2e/shell-app/app.sh). LUNEPACK_E2E_REQUIRE=1 is set, so a
# missing piece fails instead of skipping. bash 3.2 compatible.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: scripts/e2e-macos.sh [--ci]" >&2
}

die() {
  echo "e2e-macos: $*" >&2
  exit 1
}

ci=0
while [ "$#" -gt 0 ]; do
  case $1 in
    --ci)
      ci=1
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

[ "$(uname -s)" = Darwin ] || die "refusing to run: the suite is macOS only (scripts/e2e.sh runs the Linux one)"
if [ "$(id -u)" = 0 ]; then
  die "refusing to run as root"
fi
case $(uname -m) in
  arm64) target=macos-aarch64 ;;
  x86_64) target=macos-x86_64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

# Runs a command for at most $1 seconds (perl's alarm; stdin closed). Exit 124 on a timeout.
limited() {
  local secs=$1
  shift
  perl -e '
    my $secs = shift @ARGV;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) { open(STDIN, "<", "/dev/null"); exec @ARGV or exit 127; }
    $SIG{ALRM} = sub { kill "KILL", $pid; waitpid($pid, 0); exit 124; };
    alarm $secs;
    waitpid($pid, 0);
    exit($? >> 8);
  ' "$secs" "$@"
}

# cargo and rustup find their homes through HOME: pin them before HOME moves into the root.
real_home=$HOME
export CARGO_HOME=${CARGO_HOME:-$real_home/.cargo}
export RUSTUP_HOME=${RUSTUP_HOME:-$real_home/.rustup}

root=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-e2e-mac.XXXXXX")
root=$(cd "$root" && pwd -P)
case $root in
  / | "") die "bad root" ;;
esac
mkdir -p "$root/home" "$root/build" "$root/rows"
export HOME=$root/home

cleanup() {
  status=$?
  # Detach what is mounted under the root (a row detaches its own; this is the safety net).
  mount | while IFS= read -r line; do
    point=${line#* on }
    point=${point%% (*}
    case $point in
      "$root"/*) limited 60 hdiutil detach -force "$point" >/dev/null 2>&1 || true ;;
    esac
  done
  # Unregister the bundles LaunchServices saw under the root.
  if [ -x "$lsregister" ]; then
    find "$root" -name '*.app' -type d -prune 2>/dev/null | while IFS= read -r app; do
      limited 30 "$lsregister" -u "$app" >/dev/null 2>&1 || true
    done
    # Unregister every path the database still holds under the root (bundles inside the images
    # LaunchServices saw mounted, helper apps), then count again.
    limited 120 "$lsregister" -dump 2>/dev/null | grep -E "^path:[[:space:]]+$root/" |
      sed -e 's/^path:[[:space:]]*//' -e 's/ (0x[0-9a-f]*)$//' | sort -u |
      while IFS= read -r known; do
        limited 30 "$lsregister" -u "$known" >/dev/null 2>&1 || true
      done
    # Volume and disk-image records of the images mounted under the root are the system's own
    # and name no bundle; only a line that names a `.app` counts.
    left=$(limited 120 "$lsregister" -dump 2>/dev/null | grep "$root" | grep -c '\.app' || true)
    if [ "${left:-0}" -ne 0 ]; then
      echo "e2e-macos: WARNING: lsregister -dump still lists $left bundle lines under the root" >&2
      limited 120 "$lsregister" -dump 2>/dev/null | grep "$root" | grep '\.app' | sed -e "s|$root|<root>|g" | sort -u | head -8 >&2
    else
      echo "e2e-macos: lsregister lists no bundle under the root"
    fi
  else
    echo "e2e-macos: lsregister is absent: LaunchServices registrations were not checked"
  fi
  rm -rf "$root"
  exit "$status"
}
trap cleanup EXIT

tdir=${CARGO_TARGET_DIR:-$top/target}

echo "e2e-macos: building the runtime for $target"
./scripts/build-runtime.sh "$target" --out "$root/build/lunepack-runtime"
echo "e2e-macos: building the lunepack command line, the example app and the stand-in UI"
cargo build --locked --release -p lunepack-cli
cargo build --locked --release -p lunepack --example e2e_app
cargo build --locked --release -p lunepack-runtime --example e2e_fake_ui
cp "$tdir/release/examples/e2e_app" "$root/build/e2e_app"
cp "$tdir/release/examples/e2e_fake_ui" "$root/build/e2e_fake_ui"

shell_app=$top/crates/lunepack-runtime/tests/e2e/shell-app/app.sh
[ -f "$shell_app" ] || die "the shell app is missing"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s sh "$shell_app"
fi

# How many entries named after the e2e app the real user's own folders hold.
real_entries() {
  find "$real_home/Applications" "$real_home/Library/Application Support" -maxdepth 1 \
    \( -name 'org.lunepack.e2e*' -o -name 'Lunepack E2E*' \) 2>/dev/null | wc -l | tr -d ' '
}

# The real user's own folders must not gain an entry named after the e2e app (checked at the end).
real_home=$(cd "$real_home" 2>/dev/null && pwd -P || true)
before=
if [ -n "$real_home" ] && [ "$real_home" != "$HOME" ]; then
  before=$(real_entries)
fi

echo "e2e-macos: running the suite"
LUNEPACK_E2E_ROOT=$root/rows \
  LUNEPACK_E2E_RUNTIME=$root/build/lunepack-runtime \
  LUNEPACK_E2E_CLI=$tdir/release/lunepack \
  LUNEPACK_E2E_APP=$root/build/e2e_app \
  LUNEPACK_E2E_SHELL_APP=$shell_app \
  LUNEPACK_E2E_FAKE_UI=$root/build/e2e_fake_ui \
  LUNEPACK_E2E_UI=$root/build/e2e_fake_ui \
  LUNEPACK_E2E_CI=$ci \
  LUNEPACK_E2E_REQUIRE=1 \
  cargo test --locked -p lunepack-runtime --test e2e

if [ -n "$real_home" ] && [ "$real_home" != "$HOME" ]; then
  after=$(real_entries)
  [ "$after" = "$before" ] || die "FAIL: the real user's folders gained an e2e entry"
fi
echo "e2e-macos: PASS"
