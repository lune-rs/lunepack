#!/usr/bin/env bash
# The user-run check of real macOS code signing, notarization and publisher continuity (M9 step 10;
# M9-D11, M9-D12). CI proves the mechanics with ad-hoc and throwaway identities; only a Developer ID
# identity and Apple's notary service can show that a release lunepack packed is accepted, stapled
# and trusted by Gatekeeper. A person runs this at a Mac that holds the identity.
#
#   scripts/macos-sign-check.sh [--dry-run] [--rcodesign]
#   scripts/macos-sign-check.sh --windows-note
#
# What it needs, named by environment variable (names are all this script ever reads; no value is
# printed, logged or put in an argument list of a process it starts, and the key file is never read):
#   LUNEPACK_SIGN_IDENTITY      a Developer ID Application identity in the login keychain (a name or
#                               a hash; not a secret)
#   LUNEPACK_NOTARY_KEY         the path of the App Store Connect API key file (outside every git
#                               checkout, a regular file of mode 0600; recommended place:
#                               ~/.config/lunepack-rs/notary/)
#   LUNEPACK_NOTARY_KEY_ID      the key's id
#   LUNEPACK_NOTARY_ISSUER      the issuer id
# `--rcodesign` also needs Docker, LUNEPACK_RCODESIGN_IMAGE (the name of an image that has
# `rcodesign` on its PATH) and LUNEPACK_NOTARY_JSON (the path of the API-key JSON that
# `rcodesign encode-app-store-connect-api-key` wrote, held to the same rules as the key).
#
# It builds the runtime, the command line, the real `lunepack-ui` and the example app, then:
#   1. packs 1.0.0 and 1.1.0 through `[codesign.macos]` (hardened-runtime signing, notarization
#      with `notarytool`, stapling with `stapler`), builds the `.dmg` and the `.zip` installers
#      (the installer app and the image signed, notarized and stapled too);
#   2. records one verdict per row, PASS, FAIL or INVALID (a row whose control did not behave as
#      expected is INVALID, never PASS), SKIPPED when a row did not run:
#        - the notary accepted every submission of this run (its status word only);
#        - `stapler validate` on the bundle and on the image (control: an ad-hoc copy fails it);
#        - `spctl` accepts the bundle as a notarized Developer ID app (control: an ad-hoc copy is
#          rejected);
#        - the staged update holds the staple ticket, `Contents/CodeResources`;
#        - a quarantined copy of the image, and the installer app on it, pass Gatekeeper's
#          assessment (an assessment: no window is opened);
#        - an app copy with the quarantine attribute, started through LaunchServices from the temp
#          root's Downloads, runs translocated and its runtime refuses with exit 28 `translocated`;
#        - continuity under `enforce`: 1.0.0 updates to 1.1.0 (the positive control), the update is
#          applied and the swapped bundle verifies and is accepted; an ad-hoc 1.2.0 is refused with
#          exit 29 `candidate_unsigned` and never offered again;
#        - optional `--rcodesign`: the same bundle notarized from Linux, in Docker, with the key
#          directory mounted read-only.
#   The report holds verdicts and tool exit statuses only; it is printed at the end.
#
#   --dry-run       needs no credentials: it builds and packs with ad-hoc signing and no
#                   notarization, builds the installers, then lists every real row as SKIPPED with
#                   its reason. It tells which credentials are missing or wrong, by variable name.
#   --windows-note  prints how to run the optional Windows real row on a Windows machine (not run
#                   here) and exits.
#
# Everything lives under one `mktemp -d` root (canonical): the app's `HOME` is `<root>/home`, the
# disk images are mounted under the root (never in /Volumes), and the trap detaches them, stops what
# still runs from them, unregisters the bundles LaunchServices saw (`lsregister -u`) and removes the
# root. No sudo. Nothing outside the root is written except LaunchServices' own records of the temp
# bundles (the trap removes them), the keychain's use of the identity, and Apple's notary service
# (network, your account). `set -x` is never enabled. bash 3.2 compatible.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: scripts/macos-sign-check.sh [--dry-run] [--rcodesign] | --windows-note" >&2
}

die() {
  echo "macos-sign-check: $*" >&2
  exit 1
}

dry_run=0
rcodesign=0
windows_note=0
while [ "$#" -gt 0 ]; do
  case $1 in
    --dry-run)
      dry_run=1
      shift
      ;;
    --rcodesign)
      rcodesign=1
      shift
      ;;
    --windows-note)
      windows_note=1
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
if [ "$windows_note" -eq 1 ] && { [ "$dry_run" -eq 1 ] || [ "$rcodesign" -eq 1 ]; }; then
  usage
  exit 2
fi

if [ "$windows_note" -eq 1 ]; then
  cat <<'EOF'
The optional Windows real row (run on a Windows machine, not here)

1. Put a [codesign.windows] section in lunepack.toml. Templates hold paths, ids and
   names only, never a secret value (a secret reaches the tool through its own environment
   or files). Examples, each with a timestamp so the signature outlives the certificate:
     sign = ["signtool", "sign", "/fd", "sha256", "/tr", "<timestamp service URL>", "/td", "sha256",
             "/sha1", "{env:LUNEPACK_WIN_CERT_SHA1}", "{path}"]
     verify = ["signtool", "verify", "/pa", "{path}"]
   (a certificate in the user's store; for a remote signer, the tool's own arguments with
   `{path}` as the file argument.)
2. Pack two releases of a small app (1.0.0 and 1.1.0) with `lunepack pack`, build `Setup.exe`
   with `lunepack setup`, and run `signtool verify /pa` on the Setup and on the app's
   executable.
3. Install 1.0.0 from the Setup, then update to 1.1.0 with `lunepack-runtime download` and
   check that it stages. Pack a 1.2.0 signed by a different certificate (or unsigned): `download`
   must exit 29 `publisher_mismatch`, and `check` must not offer 1.2.0 again.
4. Record each result as PASS or FAIL with the exit status; do not paste certificate names,
   thumbprints or paths.
EOF
  exit 0
fi

[ "$(uname -s)" = Darwin ] || die "refusing to run: macOS only (the rows need codesign, notarytool, stapler, spctl and LaunchServices)"
if [ "$(id -u)" = 0 ]; then
  die "refusing to run as root"
fi
case $(uname -m) in
  arm64) target=macos-aarch64 ;;
  x86_64) target=macos-x86_64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

# ---- credentials: names only; the key file is looked at with stat, never read -----------------

sign_vars="LUNEPACK_SIGN_IDENTITY LUNEPACK_NOTARY_KEY LUNEPACK_NOTARY_KEY_ID LUNEPACK_NOTARY_ISSUER"
secret_vars="$sign_vars LUNEPACK_NOTARY_JSON"
main_repo=$(cd "$(git rev-parse --git-common-dir)/.." 2>/dev/null && pwd -P || echo "$top")

# Why the variable $1 (naming a file) is unusable, without naming its value; nothing when it is fine.
secret_file_problem() {
  local name=$1 p kind mode dir
  p=${!name:-}
  [ -n "$p" ] || {
    echo "is not set"
    return 0
  }
  case $p in
    /*) ;;
    *)
      echo "is not an absolute path"
      return 0
      ;;
  esac
  kind=$(/usr/bin/stat -f '%HT' "$p" 2>/dev/null) || {
    echo "does not name an existing file"
    return 0
  }
  if [ "$kind" != "Regular File" ]; then
    echo "is not a regular file (a link or a directory is refused)"
    return 0
  fi
  mode=$(/usr/bin/stat -f '%Lp' "$p" 2>/dev/null || true)
  if [ "$mode" != 600 ]; then
    echo "is not mode 0600"
    return 0
  fi
  dir=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd -P) || {
    echo "has no readable folder"
    return 0
  }
  case "$dir/" in
    "$top"/* | "$main_repo"/*)
      echo "is inside this repository"
      return 0
      ;;
  esac
  if git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "is inside a git checkout"
    return 0
  fi
  return 0
}

# Prints one line per unusable credential variable (names only). Returns 1 when there is any.
credential_problems() {
  local bad=0 name why
  for name in LUNEPACK_SIGN_IDENTITY LUNEPACK_NOTARY_KEY_ID LUNEPACK_NOTARY_ISSUER; do
    if [ -z "${!name:-}" ]; then
      echo "$name is not set"
      bad=1
    fi
  done
  why=$(secret_file_problem LUNEPACK_NOTARY_KEY)
  if [ -n "$why" ]; then
    echo "LUNEPACK_NOTARY_KEY $why"
    bad=1
  fi
  if [ "$rcodesign" -eq 1 ]; then
    why=$(secret_file_problem LUNEPACK_NOTARY_JSON)
    if [ -n "$why" ]; then
      echo "LUNEPACK_NOTARY_JSON $why"
      bad=1
    fi
    if [ -z "${LUNEPACK_RCODESIGN_IMAGE:-}" ]; then
      echo "LUNEPACK_RCODESIGN_IMAGE is not set"
      bad=1
    fi
  fi
  return "$bad"
}

problems=$(credential_problems || true)
if [ "$dry_run" -eq 0 ] && [ -n "$problems" ]; then
  echo "macos-sign-check: refusing to run; nothing was built or touched:" >&2
  printf '%s\n' "$problems" | sed -e 's/^/  /' >&2
  echo "macos-sign-check: see the header of this script for what each variable is" >&2
  exit 1
fi

tools="/usr/bin/hdiutil /usr/bin/codesign /usr/bin/xattr /usr/sbin/spctl /usr/bin/python3 /usr/bin/perl /usr/bin/ditto /usr/bin/curl /usr/bin/open /usr/bin/stat /usr/bin/xcrun"
for tool in $tools; do
  [ -x "$tool" ] || die "$tool is missing"
done
if [ "$dry_run" -eq 0 ]; then
  /usr/bin/xcrun --find notarytool >/dev/null 2>&1 || die "xcrun cannot find notarytool (install Xcode's command line tools)"
  /usr/bin/xcrun --find stapler >/dev/null 2>&1 || die "xcrun cannot find stapler"
  if [ "$rcodesign" -eq 1 ]; then
    command -v docker >/dev/null 2>&1 || die "--rcodesign needs docker on the PATH"
  fi
fi

app_id=org.lunepack.signcheck
app_name="Lunepack Sign Check"
entry=lunepack-signcheck
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

# The real home stays the home of the packager and of the signing tools (the keychain lives there);
# the app's own runs get the temporary one.
real_home=$(cd "$HOME" && pwd -P)
export CARGO_HOME=${CARGO_HOME:-$real_home/.cargo}
export RUSTUP_HOME=${RUSTUP_HOME:-$real_home/.rustup}

root=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-signcheck.XXXXXX")
root=$(cd "$root" && pwd -P)
case $root in
  / | "") die "bad root" ;;
esac
mkdir -p "$root/build" "$root/work" "$root/pub" "$root/mnt" "$root/release" "$root/log" "$root/home" "$root/Downloads"
home=$root/home
data_dir=$home/Library/Application\ Support/$app_id
bundle=$home/Applications/$app_name.app
out_file=$root/outcome.txt
report=$root/report.txt
: >"$out_file"
: >"$report"
server_pid=
started=$(date -u +%Y-%m-%dT%H:%M:%S)
n_pass=0
n_fail=0
n_invalid=0
n_skip=0

# Control characters out, the root named, every credential variable's value replaced by its name,
# long lines cut. Everything the script prints from a tool's output passes here.
scrub() {
  local text name val
  text=$(LC_ALL=C tr -cd '[:print:]\n' | head -c 4096)
  for name in $secret_vars; do
    val=${!name:-}
    # Only a value long enough to be one (a one-character value would mangle the text).
    if [ "${#val}" -ge 4 ]; then
      text=${text//"$val"/<$name>}
    fi
  done
  printf '%s\n' "$text" | sed -e "s|$root|<root>|g" -e 's|^\(.\{200\}\).*|\1...|'
}

# One verdict row: <PASS|FAIL|INVALID|SKIPPED> <id> <what> <detail: statuses only>
row() {
  local line
  line="$1 $2: $3"
  if [ -n "${4:-}" ]; then line="$line ($4)"; fi
  printf '%s\n' "$line" | scrub >>"$report"
  printf '  %s\n' "$line" | scrub
  case $1 in
    PASS) n_pass=$((n_pass + 1)) ;;
    FAIL) n_fail=$((n_fail + 1)) ;;
    INVALID) n_invalid=$((n_invalid + 1)) ;;
    SKIPPED) n_skip=$((n_skip + 1)) ;;
  esac
}

# What a failed step shows: its exit status and the scrubbed tail of its own log.
show_failure() { # <what> <status> <log>
  echo "macos-sign-check: $1 failed (exit $2); the tail of its output:" >&2
  tail -c 2000 "$3" 2>/dev/null | scrub >&2 || true
}

# shellcheck disable=SC2329 # called by the EXIT trap's cleanup
stage_unregister() {
  [ -x "$lsregister" ] || return 0
  limited 30 "$lsregister" -u "$1" >/dev/null 2>&1 || true
}

reported=0
finish() {
  reported=1
  echo
  echo "macos-sign-check: the report"
  cat "$report"
  echo "macos-sign-check: $n_pass PASS, $n_fail FAIL, $n_invalid INVALID, $n_skip SKIPPED"
  if [ "$n_fail" -ne 0 ] || [ "$n_invalid" -ne 0 ]; then
    exit 1
  fi
  exit 0
}

# shellcheck disable=SC2329 # the EXIT trap
cleanup() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "$reported" -eq 0 ] && [ -s "$report" ]; then
    echo "macos-sign-check: stopped early; the report so far:"
    cat "$report"
  fi
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  # What still runs from under the root, and the translocated copy of the app (it runs from a
  # system path, found by the entry's unique name).
  ps -axo pid=,args= 2>/dev/null | awk -v root="$root/" -v entry="/Contents/MacOS/$entry" -v me="$$" '
    $1 != me && index($0, " -v root=") == 0 && (index($0, root) > 0 || index($0, entry) > 0) { print $1 }
  ' | while IFS= read -r pid; do
    [ "$pid" = "$$" ] || kill "$pid" 2>/dev/null || true
  done
  mount | while IFS= read -r line; do
    point=${line#* on }
    point=${point%% (*}
    case $point in
      "$root"/*) limited 60 hdiutil detach -force "$point" >/dev/null 2>&1 || true ;;
    esac
  done
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
      echo "macos-sign-check: WARNING: lsregister -dump still lists $left bundle lines under the root" >&2
    else
      echo "macos-sign-check: lsregister lists no bundle under the root"
    fi
  else
    echo "macos-sign-check: lsregister is absent: LaunchServices registrations were not checked"
  fi
  rm -rf "$root"
  exit "$status"
}
trap cleanup EXIT

{
  echo "lunepack sign check, $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "macOS $(sw_vers -productVersion 2>/dev/null || echo unknown), $(uname -m), commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if [ "$dry_run" -eq 1 ]; then echo "mode: dry run (ad-hoc signing, no notarization)"; else echo "mode: real identity"; fi
  echo
} >>"$report"

if [ "$dry_run" -eq 1 ]; then
  if [ -n "$problems" ]; then
    echo "macos-sign-check: dry run; a real run would refuse for now:"
    printf '%s\n' "$problems" | sed -e 's/^/  /'
  else
    echo "macos-sign-check: dry run; the credential variables look usable (a real run can start)"
  fi
fi

# ---- build ---------------------------------------------------------------------------------

tdir=${CARGO_TARGET_DIR:-$top/target}
echo "macos-sign-check: building the runtime for $target"
limited 3600 ./scripts/build-runtime.sh "$target" --out "$root/build/lunepack-runtime" >"$root/log/build.log" 2>&1 ||
  {
    show_failure "the runtime build" $? "$root/log/build.log"
    exit 1
  }
echo "macos-sign-check: building the command line, the example app and the real lunepack-ui"
for pkg_args in "-p lunepack-cli" "-p lunepack --example e2e_app" "-p lunepack-ui"; do
  # shellcheck disable=SC2086 # the package arguments are words on purpose
  limited 3600 cargo build --locked --release $pkg_args >>"$root/log/build.log" 2>&1 ||
    {
      show_failure "cargo build $pkg_args" $? "$root/log/build.log"
      exit 1
    }
done
cli=$tdir/release/lunepack
for f in "$cli" "$tdir/release/examples/e2e_app" "$tdir/release/lunepack-ui"; do
  [ -f "$f" ] || die "the build left no $f"
done
cp "$tdir/release/examples/e2e_app" "$root/build/e2e_app"
cp "$tdir/release/lunepack-ui" "$root/build/lunepack-ui"
runtime_bin=$root/build/lunepack-runtime
ui_bin=$root/build/lunepack-ui

# The command line. It inherits the environment (the signing tools need the keychain's HOME, their
# PATH and the credential variables the templates name); nothing here prints the environment.
cli_run() {
  (cd "$root/work" && limited 7200 "$cli" "$@")
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

# ---- the publisher -------------------------------------------------------------------------

pub=$root/pub
public_of() { # <key name>
  cli_run keys gen "$pub/$1.key" | sed -n 's/^public: //p' | head -n 1 | tr -d '[:space:]'
}
root_pub=$(public_of root)
release_pub=$(public_of release)
[ -n "$root_pub" ] && [ -n "$release_pub" ] || die "keys gen printed no public key"

# write_config <file> <real|adhoc>: the packaging configuration. `real` is the user's identity and
# notarization (templates name environment variables only, M9-D1); `adhoc` signs ad hoc and nothing
# else. `publisher_check` takes its default: enforce, because a [codesign.macos] section exists.
write_config() {
  local file=$1 mode=$2
  {
    cat <<EOF
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
comment = "The lunepack sign check app"

[codesign.macos]
EOF
    if [ "$mode" = real ]; then
      cat <<'EOF'
sign = ["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp", "--sign", "{env:LUNEPACK_SIGN_IDENTITY}", "{path}"]
verify = ["/usr/bin/codesign", "--verify", "--deep", "--strict", "{path}"]
notarize = ["/usr/bin/xcrun", "notarytool", "submit", "{zip}", "--key", "{env:LUNEPACK_NOTARY_KEY}", "--key-id", "{env:LUNEPACK_NOTARY_KEY_ID}", "--issuer", "{env:LUNEPACK_NOTARY_ISSUER}", "--wait"]
staple = ["/usr/bin/xcrun", "stapler", "staple", "{path}"]
EOF
    else
      cat <<'EOF'
sign = ["/usr/bin/codesign", "--force", "--sign", "-", "{path}"]
verify = ["/usr/bin/codesign", "--verify", "--deep", "--strict", "{path}"]
EOF
    fi
  } >"$file"
}

if [ "$dry_run" -eq 1 ]; then main_mode=adhoc; else main_mode=real; fi
cfg_main=$pub/lunepack.toml
cfg_adhoc=$pub/lunepack-adhoc.toml
write_config "$cfg_main" "$main_mode"
write_config "$cfg_adhoc" adhoc
cli_run keys set --release-dir "$rd" --release-key "$release_pub" --sign root --config "$cfg_main" >/dev/null

# publish <version> <config>: packs a bundle of that version into the release directory.
publish() {
  local ver=$1 cfg=$2 input
  input=$root/work/in-$ver
  mkdir -p "$input/Contents/MacOS" "$input/Contents/Resources"
  cat >"$input/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$entry</string>
<key>CFBundleIdentifier</key><string>org.lunepack.signcheck.app</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>$app_name</string>
<key>CFBundleShortVersionString</key><string>$ver</string>
</dict></plist>
EOF
  cp "$root/build/e2e_app" "$input/Contents/MacOS/$entry"
  chmod 755 "$input/Contents/MacOS/$entry"
  printf '%s\n' "$ver" >"$input/Contents/Resources/version.txt"
  cli_run pack --input "$input" --version "$ver" --target "$target" --runtime "$runtime_bin" \
    --ui "$ui_bin" --release-dir "$rd" --sign release --config "$cfg" >"$root/log/pack-$ver.log" 2>&1
}

feed_add() { # <version>
  cli_run feed add --release-dir "$rd" --channel stable --version "$1" --sign release --config "$cfg_main" >/dev/null
}

if [ "$dry_run" -eq 1 ]; then
  echo "macos-sign-check: packing 1.0.0 and 1.1.0 (ad-hoc signed, no notarization: dry run)"
else
  echo "macos-sign-check: packing 1.0.0 and 1.1.0 (signing and notarizing; this takes a while)"
fi
packed_ok=1
for ver in 1.0.0 1.1.0; do
  code=0
  publish "$ver" "$cfg_main" || code=$?
  if [ "$code" -ne 0 ]; then
    show_failure "pack $ver" "$code" "$root/log/pack-$ver.log"
    packed_ok=0
    break
  fi
  feed_add "$ver"
done
dmg=$root/work/$app_id-1.0.0.dmg
zip=$root/work/$app_id-1.0.0.zip
setup_ok=0
if [ "$packed_ok" -eq 1 ]; then
  code=0
  cli_run setup "$rd" --version 1.0.0 --target "$target" --out "$dmg" --config "$cfg_main" >"$root/log/setup-dmg.log" 2>&1 || code=$?
  if [ "$code" -eq 0 ]; then
    cli_run setup "$rd" --version 1.0.0 --target "$target" --zip --out "$zip" --config "$cfg_main" >"$root/log/setup-zip.log" 2>&1 || code=$?
  fi
  if [ "$code" -ne 0 ]; then
    show_failure "setup" "$code" "$root/log/setup-dmg.log"
  elif [ -s "$dmg" ] && [ -s "$zip" ]; then
    setup_ok=1
  fi
fi

if [ "$dry_run" -eq 1 ]; then
  if [ "$packed_ok" -eq 1 ] && [ "$setup_ok" -eq 1 ]; then
    echo "macos-sign-check: dry run: packed, set up and signed ad hoc; the real rows follow, skipped"
  else
    die "dry run: the pack or the setup failed (see above)"
  fi
  reason="dry run: no credentials are used"
  row SKIPPED notary "the notary accepted every submission of this run" "$reason"
  row SKIPPED stapler "stapler validate on the bundle and the .dmg" "$reason"
  row SKIPPED spctl "Gatekeeper accepts the bundle as a notarized Developer ID app" "$reason"
  row SKIPPED ticket "the staged update holds Contents/CodeResources" "$reason"
  row SKIPPED quarantine "a quarantined .dmg and its installer app pass the assessment" "$reason"
  row SKIPPED translocated "a translocated copy's runtime exits 28 translocated" "$reason"
  row SKIPPED continuity-same "1.0.0 updates to 1.1.0 under enforce, the swapped bundle verifies" "$reason"
  row SKIPPED continuity-adhoc "an ad-hoc 1.2.0 is refused with exit 29 candidate_unsigned" "$reason"
  if [ "$rcodesign" -eq 1 ]; then
    row SKIPPED rcodesign "rcodesign notarizes the bundle from Linux in Docker" "$reason"
  fi
  finish
fi

# ---- the real rows ---------------------------------------------------------------------------

if [ "$packed_ok" -eq 0 ] || [ "$setup_ok" -eq 0 ]; then
  row FAIL pack "pack 1.0.0 and 1.1.0, then the .dmg and the .zip (signed, notarized, stapled)" "see the step's output above"
  finish
fi
row PASS pack "pack 1.0.0 and 1.1.0, then the .dmg and the .zip (signed, notarized, stapled)" "exit 0 each"

# The environment of every app process: empty but PATH, the temporary home and the outcome file.
walk_env=(env -i "PATH=$PATH" "HOME=$home" "LUNEPACK_E2E_OUT=$out_file")

attach_dmg() { # <image> <mount point> [extra hdiutil options...]
  local image=$1 point=$2
  shift 2
  mkdir -p "$point"
  limited 120 /usr/bin/hdiutil attach -nobrowse -noverify -noautoopen -readonly -mountpoint "$point" "$@" "$image" >/dev/null 2>&1
}

detach_dmg() { # <mount point>
  limited 120 /usr/bin/hdiutil detach "$1" >/dev/null 2>&1 ||
    limited 120 /usr/bin/hdiutil detach -force "$1" >/dev/null 2>&1 || true
}

wait_for() { # <seconds> <what> <command...>: polls once a second
  local secs=$1 what=$2 i=0
  shift 2
  while ! "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -le "$secs" ] || {
      echo "macos-sign-check: timed out waiting for $what" >&2
      return 1
    }
    sleep 1
  done
}

bundle_version() {
  [ "$(tr -d '[:space:]' <"$bundle/Contents/Resources/version.txt" 2>/dev/null)" = "$1" ]
}
# shellcheck disable=SC2329 # named as a command to wait_for
app_not_running() {
  ! pgrep -f -- "$bundle/Contents/" >/dev/null 2>&1
}

# ---- the bundle out of the .zip, an ad-hoc copy of it (the controls) ---------------------------

zipout=$root/zipout
mkdir -p "$zipout"
limited 300 /usr/bin/ditto -x -k "$zip" "$zipout" || die "ditto could not unpack the .zip"
zbundle=
for candidate in "$zipout"/*.app; do
  [ -d "$candidate" ] && zbundle=$candidate
done
[ -n "$zbundle" ] || die "the .zip holds no bundle"
adhoc=$root/adhoc-copy
mkdir -p "$adhoc"
limited 300 /usr/bin/ditto "$zbundle" "$adhoc/${zbundle##*/}"
abundle=$adhoc/${zbundle##*/}
limited 120 /usr/bin/codesign --force --deep --sign - "$abundle" >/dev/null 2>&1 || die "the ad-hoc control copy could not be made"

# ---- notary: every submission of this run accepted --------------------------------------------

notary_row() {
  local code=0 words total accepted w
  limited 300 /usr/bin/xcrun notarytool history --key "$LUNEPACK_NOTARY_KEY" --key-id "$LUNEPACK_NOTARY_KEY_ID" \
    --issuer "$LUNEPACK_NOTARY_ISSUER" --output-format json >"$root/history.json" 2>"$root/log/history.err" || code=$?
  if [ "$code" -ne 0 ]; then
    row FAIL notary "the notary accepted every submission of this run" "notarytool history exit $code"
    return 0
  fi
  # Only the status words of this run's submissions leave the file (created at or after the start).
  words=$(/usr/bin/python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
items = [e for e in d.get("history", []) if str(e.get("createdDate", "")) >= sys.argv[2]]
print(" ".join(str(e.get("status", "?")) for e in items))
' "$root/history.json" "$started" 2>/dev/null || true)
  total=0
  accepted=0
  for w in $words; do
    total=$((total + 1))
    if [ "$w" = Accepted ]; then accepted=$((accepted + 1)); fi
  done
  if [ "$total" -eq 0 ]; then
    row INVALID notary "the notary accepted every submission of this run" "the history lists no submission of this run"
  elif [ "$accepted" -eq "$total" ]; then
    row PASS notary "the notary accepted every submission of this run" "$total submission(s), all Accepted"
  else
    row FAIL notary "the notary accepted every submission of this run" "$accepted of $total Accepted; statuses: $words"
  fi
}
notary_row

# ---- stapler -----------------------------------------------------------------------------

stapler_row() {
  local on_bundle=0 on_dmg=0 on_adhoc=0
  limited 120 /usr/bin/xcrun stapler validate "$zbundle" >/dev/null 2>&1 || on_bundle=$?
  limited 120 /usr/bin/xcrun stapler validate "$dmg" >/dev/null 2>&1 || on_dmg=$?
  limited 120 /usr/bin/xcrun stapler validate "$abundle" >/dev/null 2>&1 || on_adhoc=$?
  if [ "$on_adhoc" -eq 0 ]; then
    row INVALID stapler "stapler validate on the bundle and the .dmg" "the control (an ad-hoc copy) validated: the instrument cannot fail"
  elif [ "$on_bundle" -eq 0 ] && [ "$on_dmg" -eq 0 ]; then
    row PASS stapler "stapler validate on the bundle and the .dmg" "exit 0 each; control exit $on_adhoc"
  else
    row FAIL stapler "stapler validate on the bundle and the .dmg" "bundle exit $on_bundle, image exit $on_dmg"
  fi
}
stapler_row

# ---- spctl -------------------------------------------------------------------------------

spctl_row() {
  local ok=0 ctl=0
  limited 120 /usr/sbin/spctl -a -t exec -vv "$zbundle" >"$root/log/spctl.log" 2>&1 || ok=$?
  limited 120 /usr/sbin/spctl -a -t exec -vv "$abundle" >/dev/null 2>&1 || ctl=$?
  if [ "$ctl" -eq 0 ]; then
    row INVALID spctl "Gatekeeper accepts the bundle as a notarized Developer ID app" "the control (an ad-hoc copy) was accepted: the instrument cannot reject"
  elif [ "$ok" -eq 0 ] && grep -q 'Notarized Developer ID' "$root/log/spctl.log"; then
    row PASS spctl "Gatekeeper accepts the bundle as a notarized Developer ID app" "exit 0, source Notarized Developer ID; control exit $ctl"
  else
    row FAIL spctl "Gatekeeper accepts the bundle as a notarized Developer ID app" "exit $ok"
  fi
}
spctl_row

# ---- quarantined .dmg ----------------------------------------------------------------------

# A quarantine attribute as a browser sets it (flags 0081, a time, an agent name, no uuid).
quarantine() { # <path>
  /usr/bin/xattr -w com.apple.quarantine "0081;$(printf '%x' "$(date +%s)");lunepack-sign-check;" "$1"
}

quarantine_row() {
  local qdmg=$root/Downloads/quarantined.dmg a=0 b=0 c=0 ctl=0 point=$root/mnt/quarantined
  cp "$dmg" "$qdmg"
  quarantine "$qdmg"
  limited 120 /usr/sbin/spctl -a -t open --context context:primary-signature -vv "$qdmg" >/dev/null 2>&1 || a=$?
  if attach_dmg "$qdmg" "$point"; then
    local installer
    installer=$(find "$point" -maxdepth 1 -name 'Install *.app' -type d | head -n 1)
    if [ -n "$installer" ]; then
      limited 120 /usr/sbin/spctl -a -t exec -vv "$installer" >/dev/null 2>&1 || b=$?
    else
      b=1
    fi
    detach_dmg "$point"
  else
    c=1
  fi
  limited 120 /usr/sbin/spctl -a -t exec -vv "$abundle" >/dev/null 2>&1 || ctl=$?
  if [ "$ctl" -eq 0 ]; then
    row INVALID quarantine "a quarantined .dmg and its installer app pass the assessment" "the control (an ad-hoc copy) was accepted"
  elif [ "$a" -eq 0 ] && [ "$b" -eq 0 ] && [ "$c" -eq 0 ]; then
    row PASS quarantine "a quarantined .dmg and its installer app pass the assessment" "image exit 0, installer exit 0, mounted; control exit $ctl"
  else
    row FAIL quarantine "a quarantined .dmg and its installer app pass the assessment" "image exit $a, installer exit $b, mount exit $c"
  fi
}
quarantine_row

# ---- translocation (M8's unproven item) ------------------------------------------------------

translocated_row() {
  local copy=$root/Downloads/${zbundle##*/} mp="" tb="" i=0 code=0 out=$root/log/translocated.out
  limited 300 /usr/bin/ditto -x -k "$zip" "$root/Downloads"
  quarantine "$copy"
  echo "macos-sign-check: starting a quarantined copy through LaunchServices; if macOS asks"
  echo "macos-sign-check: whether to open an app downloaded from the Internet, answer Open"
  limited 60 /usr/bin/open -n --env "HOME=$home" --env "LUNEPACK_E2E_OUT=$out_file" "$copy" --args --hold 40 >/dev/null 2>&1 || true
  while [ "$i" -lt 120 ] && [ -z "$tb" ]; do
    mp=$(mount | sed -n 's| on \(/.*/AppTranslocation/[^ ]*\) (nullfs.*|\1|p' | head -n 1)
    if [ -n "$mp" ]; then
      for candidate in "$mp"/*.app; do
        [ -d "$candidate" ] && tb=$candidate
      done
    fi
    [ -n "$tb" ] || sleep 0.5
    i=$((i + 1))
  done
  if [ -z "$tb" ]; then
    row INVALID translocated "a translocated copy's runtime exits 28 translocated" "the control failed: no translocated copy appeared (the quarantine did not translocate it)"
    return 0
  fi
  limited 60 "${walk_env[@]}" "$tb/Contents/MacOS/lunepack-runtime" check --json >"$out" 2>&1 || code=$?
  if [ "$code" -eq 28 ] && grep -q '"reason":"translocated"' "$out"; then
    row PASS translocated "a translocated copy's runtime exits 28 translocated" "exit 28, reason translocated"
  else
    row FAIL translocated "a translocated copy's runtime exits 28 translocated" "exit $code"
  fi
  pkill -f "/Contents/MacOS/$entry" 2>/dev/null || true
}
translocated_row

# ---- continuity under enforce ------------------------------------------------------------------

continuity_rows() {
  local code=0 mnt=$root/mnt/install installer line
  if ! attach_dmg "$dmg" "$mnt"; then
    row FAIL continuity-same "1.0.0 updates to 1.1.0 under enforce, the swapped bundle verifies" "hdiutil attach failed"
    return 0
  fi
  installer=$(find "$mnt" -maxdepth 1 -name 'Install *.app' -type d | head -n 1)
  limited 300 "${walk_env[@]}" "$installer/Contents/MacOS/lunepack-runtime" --silent >/dev/null 2>&1 || code=$?
  detach_dmg "$mnt"
  if [ "$code" -ne 0 ] || ! bundle_version 1.0.0; then
    row FAIL continuity-same "1.0.0 updates to 1.1.0 under enforce, the swapped bundle verifies" "the silent install exited $code"
    return 0
  fi
  # The positive control: the same publisher updates (no finding on the result line).
  code=0
  limited 600 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" download --json >"$root/log/download-1.1.0.out" 2>&1 || code=$?
  line=$(tail -n 1 "$root/log/download-1.1.0.out")
  if [ "$code" -ne 0 ] || ! printf '%s' "$line" | grep -q '"staged":true' || printf '%s' "$line" | grep -q '"publisher"'; then
    row FAIL continuity-same "1.0.0 updates to 1.1.0 under enforce, the swapped bundle verifies" "download exit $code"
    row SKIPPED continuity-adhoc "an ad-hoc 1.2.0 is refused with exit 29 candidate_unsigned" "the control row did not pass"
    return 0
  fi
  if [ -f "$data_dir/versions/1.1.0/Contents/CodeResources" ]; then
    row PASS ticket "the staged update holds Contents/CodeResources" "a regular file in the staged tree"
  else
    row FAIL ticket "the staged update holds Contents/CodeResources" "absent from the staged tree"
  fi
  # Apply it: the app finds the staged update and hands it to the runtime.
  limited 300 "${walk_env[@]}" "$bundle/Contents/MacOS/$entry" --update --no-ui >/dev/null 2>&1 || true
  if wait_for 120 "the swap to 1.1.0" bundle_version 1.1.0 && wait_for 60 "the runtime to end" app_not_running; then
    local v=0 g=0
    limited 120 /usr/bin/codesign --verify --deep --strict "$bundle" >/dev/null 2>&1 || v=$?
    limited 120 /usr/sbin/spctl -a -t exec -vv "$bundle" >/dev/null 2>&1 || g=$?
    if [ "$v" -eq 0 ] && [ "$g" -eq 0 ]; then
      row PASS continuity-same "1.0.0 updates to 1.1.0 under enforce, the swapped bundle verifies" "download exit 0, codesign exit 0, spctl exit 0"
    else
      row FAIL continuity-same "1.0.0 updates to 1.1.0 under enforce, the swapped bundle verifies" "codesign exit $v, spctl exit $g"
    fi
  else
    row FAIL continuity-same "1.0.0 updates to 1.1.0 under enforce, the swapped bundle verifies" "the swap did not finish"
    row SKIPPED continuity-adhoc "an ad-hoc 1.2.0 is refused with exit 29 candidate_unsigned" "the control row did not pass"
    return 0
  fi
  # The negative: an ad-hoc 1.2.0 beside the installed Developer ID publisher.
  code=0
  publish 1.2.0 "$cfg_adhoc" || code=$?
  if [ "$code" -ne 0 ]; then
    row INVALID continuity-adhoc "an ad-hoc 1.2.0 is refused with exit 29 candidate_unsigned" "the ad-hoc 1.2.0 could not be packed (exit $code)"
    return 0
  fi
  feed_add 1.2.0
  code=0
  limited 600 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" download --json >"$root/log/download-1.2.0.out" 2>&1 || code=$?
  local again=0
  limited 120 "${walk_env[@]}" "$bundle/Contents/MacOS/lunepack-runtime" check --json >"$root/log/check-after.out" 2>&1 || again=$?
  if [ "$code" -eq 29 ] && grep -q '"reason":"candidate_unsigned"' "$root/log/download-1.2.0.out" &&
    [ "$again" -eq 0 ] && grep -q '"update":null' "$root/log/check-after.out"; then
    row PASS continuity-adhoc "an ad-hoc 1.2.0 is refused with exit 29 candidate_unsigned" "download exit 29, check offers nothing afterwards"
  else
    row FAIL continuity-adhoc "an ad-hoc 1.2.0 is refused with exit 29 candidate_unsigned" "download exit $code, check exit $again"
  fi
}
continuity_rows

# ---- optional: rcodesign from Linux ------------------------------------------------------------

rcodesign_row() {
  local code=0 keydir work=$root/rcodesign-work json_name
  if [ -z "${LUNEPACK_RCODESIGN_IMAGE:-}" ]; then
    row SKIPPED rcodesign "rcodesign notarizes the bundle from Linux in Docker" "LUNEPACK_RCODESIGN_IMAGE is not set"
    return 0
  fi
  keydir=$(cd -P "$(dirname "$LUNEPACK_NOTARY_JSON")" && pwd -P)
  json_name=$(basename "$LUNEPACK_NOTARY_JSON")
  mkdir -p "$work"
  limited 300 /usr/bin/ditto "$zbundle" "$work/${zbundle##*/}"
  limited 3600 docker run --rm --tmpfs /tmp -v "$keydir:/keys:ro" -v "$work:/work" "$LUNEPACK_RCODESIGN_IMAGE" \
    rcodesign notary-submit --api-key-file "/keys/$json_name" --wait --staple "/work/${zbundle##*/}" \
    >"$root/log/rcodesign.out" 2>&1 || code=$?
  if [ "$code" -eq 0 ]; then
    row PASS rcodesign "rcodesign notarizes the bundle from Linux in Docker" "exit 0"
  else
    row FAIL rcodesign "rcodesign notarizes the bundle from Linux in Docker" "exit $code"
  fi
}
if [ "$rcodesign" -eq 1 ]; then
  rcodesign_row
fi

finish
