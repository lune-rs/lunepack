#!/usr/bin/env bash
# P-M3: the macOS root premises of the per-machine install (M11 A1, A3, A6, A7, P4; A2 headless half).
# A throwaway `.pkg` (V1: payload from `/`, with a postinstall; V2: only the leaf folder staged, no
# scripts) is installed with Apple's `installer`. V1's postinstall (root, no arguments read) copies a
# signed socket-activated daemon out of the payload, links it, swaps two folders with renamex_np,
# writes a LaunchDaemon plist and bootstraps it in the system domain. A standard user (run-time random
# password, never printed) then talks to the daemon over its socket. Control: SockPathMode 384 (0600)
# must refuse that user. Runner-only (probe_guard); everything made here is removed afterwards and no
# existing item is touched. bash 3.2.
#
# PASS needs all of: A1 (socket root-owned srw-rw-rw-; two connections served by one pid with euid 0,
# the peer credentials of the standard user and the server's euid 0 from getpeereid; a new pid after
# the idle exit), A3 (the postinstall ran as uid 0 and installer exited 0), A6 (swap rc 0 from the
# postinstall and from the daemon, markers swapped each time), A7 (codesign --verify --strict of the
# copy passes and the daemon answered from that file through the link), and a qualifying variant (P4 and
# P8): V1 or V2 installed with exit 0, left owner, group, mode and ACL of /Library and
# /Library/Application Support unchanged, and left the machine home root-owned with no group or other
# write and with search for other, and `.installer` and its leaf root-owned with no group or other bits
# and no ACL (AdminOnly). Neither variant qualifying is FAIL.
set -uo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../lib/result.sh
. "$here/../lib/result.sh"
probe_guard
probe_begin P-M3

label=lunepack-probe-m3
H="/Library/Application Support/lunepack-probe-m3"
R="$H/probe-app"
M="$R/.lunepack/machine"
A=/Applications/LpProbeM3.app
plist=/Library/LaunchDaemons/$label.plist
sock=/var/run/$label.sock
pkg_id_v1=lunepack-probe-m3.v1
pkg_id_v2=lunepack-probe-m3.v2
user=
created_by=
armed=0
work=
py=$(command -v python3)

die() { # a fatal instrument failure: INVALID through the exit trap
  probe_detail fatal "$1"
  exit 5
}

cleanup() {
  if [ "$armed" -ne 1 ]; then
    if [ -n "$work" ]; then rm -rf "$work"; fi
    return 0
  fi
  sudo -n launchctl bootout "system/$label" >/dev/null 2>&1 || true
  sudo -n rm -f "$plist" "$sock" >/dev/null 2>&1 || true
  sudo -n rm -rf "$H" "$A" >/dev/null 2>&1 || true
  sudo -n pkgutil --forget "$pkg_id_v1" >/dev/null 2>&1 || true
  sudo -n pkgutil --forget "$pkg_id_v2" >/dev/null 2>&1 || true
  if [ -n "$user" ]; then
    sudo -n sysadminctl -deleteUser "$user" >/dev/null 2>&1 || true
    if [ "$created_by" = dscl ]; then sudo -n dscl . -delete "/Users/$user" >/dev/null 2>&1 || true; fi
    sudo -n rm -rf "/Users/$user" >/dev/null 2>&1 || true
  fi
  if [ -n "$work" ]; then rm -rf "$work"; fi
}
probe_cleanup_on_exit cleanup

# Refuse (INVALID, nothing removed) when any name this probe owns already exists.
for p in "$H" "$A" "$plist" "$sock"; do
  if [ -e "$p" ] || [ -L "$p" ]; then die "a probe path already exists, nothing touched"; fi
done
armed=1
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/probe-m3.XXXXXX") || die "no work dir"

# --- helpers ---------------------------------------------------------------------------------
acl_count() { # entries below the first line of `ls -led`
  sudo -n ls -led "$1" 2>/dev/null | tail -n +2 | wc -l | tr -d ' '
}

facts() { # owner, group, mode, type and ACL entry count of one path
  local s
  s=$(sudo -n stat -f 'owner=%Su(%u) group=%Sg(%g) mode=%Lp type=%HT' "$1" 2>/dev/null) || s=missing
  printf '%s acl=%s' "$s" "$(acl_count "$1")"
}

# perm_ok <path> <home|admin>: a root-owned directory, no ACL; home: no group/other write and other
# can search; admin: no bits for group or other (M11-D7 MachineTree / AdminOnly).
perm_ok() {
  local p=$1 kind=$2 u m t a
  u=$(sudo -n stat -f %u "$p" 2>/dev/null) || return 1
  m=$(sudo -n stat -f %Lp "$p" 2>/dev/null) || return 1
  t=$(sudo -n stat -f %HT "$p" 2>/dev/null) || return 1
  a=$(acl_count "$p")
  [ "$u" = 0 ] || return 1
  [ "$t" = Directory ] || return 1
  [ "$a" = 0 ] || return 1
  case $kind in
    home) [ $((8#$m & 8#022)) -eq 0 ] && [ $((8#$m & 8#001)) -ne 0 ] ;;
    admin) [ $((8#$m & 8#077)) -eq 0 ] ;;
    *) return 1 ;;
  esac
}

record_folders() { # prefix: the five folders' facts under <prefix>_<name>
  probe_detail "$1_library" "$(facts /Library)"
  probe_detail "$1_appsupport" "$(facts "/Library/Application Support")"
  probe_detail "$1_home" "$(facts "$H")"
  probe_detail "$1_installer" "$(facts "$H/.installer")"
  probe_detail "$1_leaf" "$(facts "$H/.installer/probe-app")"
}

variant_perms_ok() { # 0 when home, .installer and the leaf pass the P8 rule
  perm_ok "$H" home && perm_ok "$H/.installer" admin && perm_ok "$H/.installer/probe-app" admin
}

fld() { # <text> <name>: the value of `name=value` among space-separated tokens
  printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1
}

run_installer() { # <pkg> -> sets INST_RC and INST_LAST (last output line, at most 160 chars)
  local out
  INST_RC=0
  out=$(probe_limited 300 sudo -n installer -pkg "$1" -target /) || INST_RC=$?
  INST_LAST=$(printf '%s\n' "$out" | tail -n 1 | cut -c 1-160)
  INST_HEAD=$(printf '%s' "$out" | tr '\n\t\r' '   ' | cut -c 1-300)
}

# install_log_since <line count>: names and results only, the lines /var/log/install.log gained since
# <line count> that mention this probe's label or a failure, at most 12 lines of 200 characters.
install_log_lines() { # the line count of /var/log/install.log now
  local n
  n=$(sudo -n cat /var/log/install.log 2>/dev/null | wc -l | tr -d ' ') || n=0
  echo "${n:-0}"
}
install_log_since() {
  sudo -n tail -n +"$(($1 + 1))" /var/log/install.log 2>/dev/null |
    grep -a -E "lunepack-probe-m3|[Ff]ail|[Ee]rror|postinstall|upgrade" |
    tail -n 12 | cut -c 1-200 | tr '\n\t\r' '   ' || true
}

record_bom() { # <prefix> <component pkg>: the BOM's own mode, owner and group of the staged folders
  local comp=$2 bomfile line name key
  bomfile=$(pkgutil --bom "$comp" 2>/dev/null | head -n 1 || true)
  if [ -z "$bomfile" ] || [ ! -f "$bomfile" ]; then
    probe_detail "$1_bom" unavailable
    return 0
  fi
  /usr/bin/lsbom -p MUGf "$bomfile" 2>/dev/null | while IFS= read -r line; do
    name=${line##*$'\t'}
    key=
    case $name in
      .) key=root ;;
      ./Library) key=library ;;
      "./Library/Application Support") key=appsupport ;;
      "./Library/Application Support/lunepack-probe-m3") key=home ;;
      "./Library/Application Support/lunepack-probe-m3/.installer") key=installer ;;
      "./Library/Application Support/lunepack-probe-m3/.installer/probe-app") key=leaf ;;
    esac
    if [ -n "$key" ]; then printf '%s\t%s\n' "$key" "$line"; fi
  done >"$work/$1.bom.txt" || true
  for key in root library appsupport home installer leaf; do
    line=$(awk -F'\t' -v k="$key" '$1 == k { print substr($0, length(k) + 2); exit }' "$work/$1.bom.txt")
    probe_detail "$1_bom_$key" "${line:-none}"
  done
}

# --- the standard user (as P-M2) -------------------------------------------------------------
probe_detail sw_vers "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
probe_detail sw_build "$(sw_vers -buildVersion 2>/dev/null || echo unknown)"
probe_detail arch "$(uname -m)"
before_lib=$(facts /Library)
before_app=$(facts "/Library/Application Support")
probe_detail before_library "$before_lib"
probe_detail before_appsupport "$before_app"

pw=$("$py" -c 'import secrets; print(secrets.token_urlsafe(18))')
user=lpprobe$(date +%s | tail -c 6)
created_by=sysadminctl
sudo -n sysadminctl -addUser "$user" -fullName "Lunepack Probe" -password "$pw" -home "/Users/$user" >/dev/null 2>&1 || true
if ! id "$user" >/dev/null 2>&1; then
  created_by=dscl
  sudo -n dscl . -create "/Users/$user"
  sudo -n dscl . -create "/Users/$user" UserShell /bin/bash
  sudo -n dscl . -create "/Users/$user" RealName "Lunepack Probe"
  sudo -n dscl . -create "/Users/$user" UniqueID 599
  sudo -n dscl . -create "/Users/$user" PrimaryGroupID 20
  sudo -n dscl . -create "/Users/$user" NFSHomeDirectory "/Users/$user"
fi
pw=
user_uid=$(id -u "$user" 2>/dev/null) || die "standard user not created"
probe_detail user_created_by "$created_by"
probe_detail non_root_user_uid "$user_uid"
admin_member=1
if id -Gn "$user" | tr ' ' '\n' | grep -qx admin; then admin_member=0; fi
probe_detail_bool user_in_admin_group "$admin_member"

# --- the daemon ------------------------------------------------------------------------------
cat >"$work/paths.h" <<HDR
#define APP_A "$A"
#define APP_S "$R/app/.swap"
#define LOG_FILE "$R/.probe/pids.txt"
HDR
cat >"$work/daemon.c" <<'CSRC'
#include <errno.h>
#include <fcntl.h>
#include <launch.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <sys/un.h>
#include <unistd.h>
#include "paths.h"

static void swap_line(char *out, size_t n) {
    int rc = renamex_np(APP_A, APP_S, RENAME_SWAP);
    snprintf(out, n, "swap=%d errno=%d", rc, rc == 0 ? 0 : errno);
}

static void log_pid(void) {
    int fd = open(LOG_FILE, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd >= 0) {
        char b[48];
        int n = snprintf(b, sizeof b, "pid=%d\n", (int)getpid());
        if (n > 0 && write(fd, b, (size_t)n) < 0) { /* best effort */ }
        close(fd);
    }
}

static void serve(int c) {
    struct xucred xu;
    socklen_t xl = sizeof xu;
    unsigned peer = (unsigned)-1;
    char line[64], reply[PATH_MAX + 64];
    size_t used = 0;
    struct timeval tv = {2, 0};
    memset(&xu, 0, sizeof xu);
    if (getsockopt(c, 0, LOCAL_PEERCRED, &xu, &xl) == 0) peer = (unsigned)xu.cr_uid;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    while (used < sizeof line - 1) {
        ssize_t n = read(c, line + used, sizeof line - 1 - used);
        if (n <= 0) break;
        used += (size_t)n;
        if (memchr(line, '\n', used)) break;
    }
    line[used] = 0;
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;
    if (strcmp(line, "id") == 0) {
        snprintf(reply, sizeof reply, "pid=%d euid=%d peer_uid=%u\n", (int)getpid(), (int)geteuid(), peer);
    } else if (strcmp(line, "swap") == 0) {
        char s[64];
        swap_line(s, sizeof s);
        snprintf(reply, sizeof reply, "%s\n", s);
    } else if (strcmp(line, "exe") == 0) {
        char raw[PATH_MAX], real[PATH_MAX];
        uint32_t sz = sizeof raw;
        if (_NSGetExecutablePath(raw, &sz) == 0 && realpath(raw, real)) {
            snprintf(reply, sizeof reply, "exe=%s\n", real);
        } else {
            snprintf(reply, sizeof reply, "exe=error\n");
        }
    } else {
        snprintf(reply, sizeof reply, "error=unknown\n");
    }
    if (write(c, reply, strlen(reply)) < 0) { /* the client left */ }
    close(c);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "swap") == 0) {
        char s[64];
        swap_line(s, sizeof s);
        puts(s);
        return 0;
    }
    int *fds = NULL;
    size_t cnt = 0;
    int rc = launch_activate_socket("lunepack", &fds, &cnt);
    if (rc != 0 || cnt != 1 || fds == NULL) {
        fprintf(stderr, "launch_activate_socket rc=%d count=%zu\n", rc, cnt);
        return 2;
    }
    int lfd = fds[0];
    free(fds);
    log_pid();
    for (;;) {
        struct pollfd p = {lfd, POLLIN, 0};
        int r = poll(&p, 1, 5000);
        if (r == 0) return 0; /* idle exit */
        if (r < 0) {
            if (errno == EINTR) continue;
            return 3;
        }
        int c = accept(lfd, NULL, NULL);
        if (c >= 0) serve(c);
    }
}
CSRC
cat >"$work/main.c" <<'CSRC'
int main(void) { return 0; }
CSRC

probe_limited 120 cc -O1 -Wall -Wno-deprecated-declarations -I "$work" -o "$work/lunepack-service" "$work/daemon.c" >"$work/cc1.txt" 2>&1 || {
  probe_detail cc_daemon_tail "$(tail -n 3 "$work/cc1.txt" | tr '\n' ' ')"
  die "cannot compile the daemon"
}
probe_limited 120 cc -O1 -o "$work/main" "$work/main.c" >/dev/null 2>&1 || die "cannot compile the main executable"

# The source bundle, ordered as C7 orders nested code: the helper first (standalone), then the bundle.
src="$work/LpProbeM3-src.app"
mkdir -p "$src/Contents/MacOS"
cp "$work/lunepack-service" "$src/Contents/MacOS/lunepack-service"
cp "$work/main" "$src/Contents/MacOS/main"
cat >"$src/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>lunepack-probe-m3.src</string>
  <key>CFBundleExecutable</key><string>main</string>
  <key>CFBundleName</key><string>LpProbeM3-src</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
probe_limited 60 codesign --force --sign - -i lunepack-probe-m3.service "$src/Contents/MacOS/lunepack-service" >/dev/null 2>&1 || die "cannot sign the helper"
probe_limited 60 codesign --force --sign - "$src" >/dev/null 2>&1 || die "cannot sign the source bundle"
rc=0
probe_limited 60 codesign --verify --strict "$src" >/dev/null 2>&1 || rc=$?
probe_detail src_bundle_verify_rc "$rc"
rc=0
probe_limited 60 codesign --verify --strict "$src/Contents/MacOS/lunepack-service" >/dev/null 2>&1 || rc=$?
probe_detail src_helper_verify_rc "$rc"

# --- the two packages ------------------------------------------------------------------------
# component_plist <file> <bundle path relative to the payload root>: no relocation, no version check
component_plist() {
  cat >"$1" <<CPL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array><dict>
  <key>RootRelativeBundlePath</key><string>$2</string>
  <key>BundleHasStrictIdentifier</key><false/>
  <key>BundleIsRelocatable</key><false/>
  <key>BundleIsVersionChecked</key><false/>
  <key>BundleOverwriteAction</key><string>upgrade</string>
</dict></array></plist>
CPL
}

pkg_fail() { # <name> <log file>: the last lines of a failed build tool, then INVALID
  probe_detail "build_$1_tail" "$(tail -n 2 "$2" | tr '\n' ' ' | cut -c 1-200)"
  die "$1 build failed"
}

# build_pkg <name> <identifier> <stage> <install-location> <component plist> [<scripts dir>]
build_pkg() {
  local name=$1 id=$2 stage=$3 loc=$4 cpl=$5 scripts=${6:-}
  mkdir -p "$work/pkgs/$name"
  if [ -n "$scripts" ]; then
    probe_limited 120 pkgbuild --root "$stage" --install-location "$loc" --scripts "$scripts" \
      --component-plist "$cpl" --identifier "$id" --version 1 --ownership recommended \
      "$work/pkgs/$name/component.pkg" >"$work/pkgbuild-$name.txt" 2>&1 || pkg_fail "pkgbuild-$name" "$work/pkgbuild-$name.txt"
  else
    probe_limited 120 pkgbuild --root "$stage" --install-location "$loc" \
      --component-plist "$cpl" --identifier "$id" --version 1 --ownership recommended \
      "$work/pkgs/$name/component.pkg" >"$work/pkgbuild-$name.txt" 2>&1 || pkg_fail "pkgbuild-$name" "$work/pkgbuild-$name.txt"
  fi
  cat >"$work/$name.dist.xml" <<DIST
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Lunepack Probe M3 $name</title>
  <domains enable_localSystem="true" enable_currentUserHome="false" enable_anywhere="false"/>
  <options customize="never" require-scripts="false"/>
  <choices-outline><line choice="default"><line choice="$id"/></line></choices-outline>
  <choice id="default"/>
  <choice id="$id" visible="false"><pkg-ref id="$id"/></choice>
  <pkg-ref id="$id" version="1">component.pkg</pkg-ref>
</installer-gui-script>
DIST
  probe_limited 120 productbuild --distribution "$work/$name.dist.xml" --package-path "$work/pkgs/$name" \
    "$work/$name.pkg" >"$work/productbuild-$name.txt" 2>&1 || pkg_fail "productbuild-$name" "$work/productbuild-$name.txt"
}

# V1: payload from `/`, the five folders staged, with a postinstall.
leaf1="Library/Application Support/lunepack-probe-m3/.installer/probe-app"
stage1=$work/stage-v1
mkdir -p "$stage1/$leaf1"
cp -R "$src" "$stage1/$leaf1/LpProbeM3-src.app"
chmod 0755 "$stage1/Library" "$stage1/Library/Application Support" "$stage1/Library/Application Support/lunepack-probe-m3"
chmod 0700 "$stage1/Library/Application Support/lunepack-probe-m3/.installer" "$stage1/$leaf1"

mkdir -p "$work/scripts"
{
  printf '#!/bin/bash\n'
  printf 'H=%q\nR=%q\nA=%q\nLABEL=%q\nSOCK=%q\nPLIST=%q\n' "$H" "$R" "$A" "$label" "$sock" "$plist"
  cat <<'BODY'
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
um=$(umask)
cwd=$(pwd)
envn=$(env | wc -l | tr -d ' ')
if [ -n "${HOME+x}" ]; then home_set=yes; else home_set=no; fi
uid=$(id -u)
status=0
umask 022
SRC="$H/.installer/probe-app/LpProbeM3-src.app"
M="$R/.lunepack/machine"
install -d -m 0755 -o root -g wheel "$R" "$R/.lunepack" "$M" "$M/service" "$M/service/1" || status=1
install -d -m 0700 -o root -g wheel "$R/.probe" || status=1
{
  echo "euid=$uid"
  echo "umask=$um"
  echo "pwd=$cwd"
  echo "env_lines=$envn"
  echo "home_set=$home_set"
} > "$R/.probe/postinstall.txt"
chmod 0600 "$R/.probe/postinstall.txt"
cp "$SRC/Contents/MacOS/lunepack-service" "$M/service/1/lunepack-service" || status=1
chown root:wheel "$M/service/1/lunepack-service"
chmod 0755 "$M/service/1/lunepack-service"
ln -sfn service/1/lunepack-service "$M/lunepack-service.new" || status=1
mv -f "$M/lunepack-service.new" "$M/lunepack-service" || status=1
if [ ! -d "$R/app/.swap" ]; then
  install -d -m 0755 -o root -g wheel "$R/app" "$R/app/.swap"
  : > "$R/app/.swap/b"
fi
"$M/service/1/lunepack-service" swap > "$R/.probe/postinstall-swap.txt" 2>&1
if grep -q '^swap=0 ' "$R/.probe/postinstall-swap.txt"; then echo "swap_rc=0" >> "$R/.probe/postinstall.txt"; else echo "swap_rc=1" >> "$R/.probe/postinstall.txt"; status=1; fi
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$M/lunepack-service</string></array>
  <key>Sockets</key>
  <dict>
    <key>lunepack</key>
    <dict>
      <key>SockPathName</key><string>$SOCK</string>
      <key>SockPathMode</key><integer>438</integer>
    </dict>
  </dict>
</dict>
</plist>
PLISTEOF
chown root:wheel "$PLIST"
chmod 0644 "$PLIST"
launchctl bootout "system/$LABEL" >/dev/null 2>&1
bmsg=$(launchctl bootstrap system "$PLIST" 2>&1)
brc=$?
echo "bootstrap_rc=$brc" >> "$R/.probe/postinstall.txt"
echo "bootstrap_msg=$(printf '%s' "$bmsg" | tr '\n' ' ' | cut -c 1-120)" >> "$R/.probe/postinstall.txt"
if [ "$brc" -ne 0 ]; then status=1; fi
exit $status
BODY
} >"$work/scripts/postinstall"
chmod 0755 "$work/scripts/postinstall"

component_plist "$work/v1.cpl.plist" "$leaf1/LpProbeM3-src.app"
build_pkg v1 "$pkg_id_v1" "$stage1" / "$work/v1.cpl.plist" "$work/scripts"
record_bom v1 "$work/pkgs/v1/component.pkg"

# V2: only the leaf's contents staged, the leaf as the install location, no scripts.
stage2=$work/stage-v2
mkdir -p "$stage2"
cp -R "$src" "$stage2/LpProbeM3-src.app"
chmod 0700 "$stage2"
component_plist "$work/v2.cpl.plist" "LpProbeM3-src.app"
build_pkg v2 "$pkg_id_v2" "$stage2" "$H/.installer/probe-app" "$work/v2.cpl.plist"
record_bom v2 "$work/pkgs/v2/component.pkg"

# --- client and plist helpers ----------------------------------------------------------------
cat >"$work/client.py" <<'PY'
import ctypes, errno, socket, sys, time
path, cmd = sys.argv[1], sys.argv[2]
t0 = time.time()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
try:
    s.connect(path)
except OSError as e:
    print("connect=error errno=%s name=%s" % (e.errno, errno.errorcode.get(e.errno, "?")))
    sys.exit(0)
libc = ctypes.CDLL(None, use_errno=True)
u = ctypes.c_uint32()
g = ctypes.c_uint32()
rc = libc.getpeereid(s.fileno(), ctypes.byref(u), ctypes.byref(g))
server = u.value if rc == 0 else -1
data = b""
try:
    s.sendall((cmd + "\n").encode())
    while True:
        chunk = s.recv(512)
        if not chunk:
            break
        data += chunk
except OSError as e:
    print("connect=ok io_error=%s server_euid=%d" % (errno.errorcode.get(e.errno, "?"), server))
    sys.exit(0)
print("connect=ok server_euid=%d elapsed=%.1f reply=%s" % (server, time.time() - t0, data.decode("ascii", "replace").strip()))
PY

client() { # <command>: as the standard user; "connect=ok ..." or "connect=error errno=N name=X"
  # shellcheck disable=SC2024  # the script file is read by this shell on purpose
  (cd / && sudo -n -u "$user" "$py" - "$sock" "$1" <"$work/client.py") 2>/dev/null || true
}

write_plist() { # SockPathMode as a decimal integer (the postinstall writes the same file with 438)
  sudo -n tee "$plist" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array><string>$M/lunepack-service</string></array>
  <key>Sockets</key>
  <dict>
    <key>lunepack</key>
    <dict>
      <key>SockPathName</key><string>$sock</string>
      <key>SockPathMode</key><integer>$1</integer>
    </dict>
  </dict>
</dict>
</plist>
PLIST
  sudo -n chown root:wheel "$plist"
  sudo -n chmod 0644 "$plist"
}

marker_state() { # "A=<a|b|?> S=<a|b|?>": which marker file sits in the bundle slot and the swap slot
  local x='?' y='?'
  if sudo -n test -f "$A/a"; then x=a; elif sudo -n test -f "$A/b"; then x=b; fi
  if sudo -n test -f "$R/app/.swap/a"; then y=a; elif sudo -n test -f "$R/app/.swap/b"; then y=b; fi
  printf 'A=%s S=%s' "$x" "$y"
}

activations() { sudo -n cat "$R/.probe/pids.txt" 2>/dev/null | wc -l | tr -d ' '; }

# --- V1: install, then the premises ----------------------------------------------------------
sudo -n mkdir "$A"
sudo -n sh -c ": > '$A/a'"
probe_detail markers_before "$(marker_state)"

run_installer "$work/v1.pkg"
v1_rc=$INST_RC
probe_detail v1_installer_rc "$v1_rc"
probe_detail v1_installer_last "$INST_LAST"
record_folders v1_after
v1_unchanged=no
if [ "$(facts /Library)" = "$before_lib" ] && [ "$(facts "/Library/Application Support")" = "$before_app" ]; then
  v1_unchanged=yes
fi
v1_perms=no
if variant_perms_ok; then v1_perms=yes; fi

pi=$(sudo -n cat "$R/.probe/postinstall.txt" 2>/dev/null | tr '\n' ' ' || true)
pi_euid=$(fld "$pi" euid)
probe_detail postinstall_euid "${pi_euid:-none}"
probe_detail postinstall_umask "$(fld "$pi" umask)"
probe_detail postinstall_pwd "$(sudo -n sed -n 's/^pwd=//p' "$R/.probe/postinstall.txt" 2>/dev/null | head -n 1)"
probe_detail postinstall_env_lines "$(fld "$pi" env_lines)"
probe_detail postinstall_home_set "$(fld "$pi" home_set)"
probe_detail postinstall_swap_rc "$(fld "$pi" swap_rc)"
probe_detail postinstall_bootstrap_rc "$(fld "$pi" bootstrap_rc)"
probe_detail postinstall_bootstrap_msg "$(sudo -n sed -n 's/^bootstrap_msg=//p' "$R/.probe/postinstall.txt" 2>/dev/null | head -n 1)"
markers_pi=$(marker_state)
probe_detail markers_after_postinstall "$markers_pi"

i=0
while [ "$i" -lt 20 ] && [ ! -S "$sock" ]; do
  sleep 1
  i=$((i + 1))
done
probe_detail socket_wait_s "$i"
sock_owner=$(sudo -n stat -f %Su "$sock" 2>/dev/null || echo missing)
sock_mode=$(sudo -n stat -f %Lp "$sock" 2>/dev/null || echo missing)
sock_type=$(sudo -n stat -f %HT "$sock" 2>/dev/null || echo missing)
probe_detail socket_owner "$sock_owner"
probe_detail socket_mode "$sock_mode"
probe_detail socket_type "$sock_type"

c1=$(client id)
c2=$(client id)
probe_detail client_id_1 "$c1"
probe_detail client_id_2 "$c2"
r1=${c1#*reply=}
r2=${c2#*reply=}
pid1=$(fld "$r1" pid)
pid2=$(fld "$r2" pid)
euid1=$(fld "$r1" euid)
euid2=$(fld "$r2" euid)
peer1=$(fld "$r1" peer_uid)
peer2=$(fld "$r2" peer_uid)
server1=$(fld "$c1" server_euid)
probe_detail a2_daemon_answered_headless "$(if [ -n "$pid1" ]; then echo yes; else echo no; fi)"

exe_out=$(client exe)
exe_path=${exe_out#*reply=exe=}
probe_detail daemon_exe "$exe_path"
expected_exe="$M/service/1/lunepack-service"
a7_codesign_rc=0
probe_limited 60 codesign --verify --strict "$expected_exe" >/dev/null 2>&1 || a7_codesign_rc=$?
probe_detail copy_codesign_verify_rc "$a7_codesign_rc"
probe_detail link_target "$(sudo -n readlink "$M/lunepack-service" 2>/dev/null || echo none)"

sw=$(client swap)
probe_detail client_swap "$sw"
sw_reply=${sw#*reply=}
markers_dm=$(marker_state)
probe_detail markers_after_daemon_swap "$markers_dm"

sleep 8
c3=$(client id)
probe_detail client_id_after_idle "$c3"
pid3=$(fld "${c3#*reply=}" pid)
probe_detail activations "$(activations)"

btm=unavailable
if [ -x /usr/bin/sfltool ]; then
  btm_out=$(probe_limited 60 sudo -n /usr/bin/sfltool dumpbtm) && btm=no || btm=unavailable
  if [ "$btm" = no ] && printf '%s' "$btm_out" | grep -q "$label"; then btm=yes; fi
fi
probe_detail btm_lists_label "$btm"

# --- V1 again over a home set to 0711 -------------------------------------------------------
sudo -n chmod 0711 "$H"
probe_detail reinstall_home_before "$(facts "$H")"
log_mark=$(install_log_lines)
run_installer "$work/v1.pkg"
probe_detail v1_reinstall_installer_rc "$INST_RC"
probe_detail v1_reinstall_installer_last "$INST_LAST"
# Why Installer refused (or took) an upgrade over a home whose mode was changed: its own message, the
# postinstall's own record (its status lines, whether the bootstrap failed and with what) and the log lines.
probe_detail v1_reinstall_error "$INST_HEAD"
probe_detail v1_reinstall_postinstall "$(sudo -n sed -n -e '/^bootstrap_msg=/d' -e 'p' "$R/.probe/postinstall.txt" 2>/dev/null | grep -v '^pwd=' | tr '\n' ' ')"
probe_detail v1_reinstall_bootstrap_msg "$(sudo -n sed -n 's/^bootstrap_msg=//p' "$R/.probe/postinstall.txt" 2>/dev/null | head -n 1)"
probe_detail v1_reinstall_install_log "$(install_log_since "$log_mark")"
record_folders v1_reinstall

# --- control: SockPathMode 384 ---------------------------------------------------------------
# The control means: with the socket at 0600 the standard user is refused (EACCES) and the refusal
# starts no daemon. It counts daemon starts from a settled state only: the daemon of the re-install
# above is booted out first, and whatever it still had in flight (a late activation, its idle exit) is
# waited out, bounded, before the count is taken. If the state never settles, the control fails (it
# cannot tell), so a late activation is never read as the refusal starting a daemon, nor missed.
settle() { # <detail name>: wait (at most 30 s) until no daemon of this probe runs and its activation log is quiet for 3 s
  local i=0 quiet=0 prev cur
  prev=$(activations)
  while [ "$i" -lt 30 ]; do
    sleep 1
    i=$((i + 1))
    cur=$(activations)
    if ! pgrep -f "$R/.lunepack/machine/" >/dev/null 2>&1 && [ "$cur" = "$prev" ]; then
      quiet=$((quiet + 1))
    else
      quiet=0
    fi
    prev=$cur
    if [ "$quiet" -ge 3 ]; then
      probe_detail "$1" "yes after ${i}s"
      return 0
    fi
  done
  probe_detail "$1" "no after ${i}s"
  return 1
}

sudo -n launchctl bootout "system/$label" >/dev/null 2>&1 || true
settled_before=yes
settle control_settled_before || settled_before=no
sudo -n rm -f "$sock"
act_before=$(activations)
write_plist 384
sudo -n launchctl bootstrap system "$plist" >/dev/null 2>&1 || probe_detail control_bootstrap_failed yes
j=0
while [ "$j" -lt 10 ] && [ ! -S "$sock" ]; do
  sleep 1
  j=$((j + 1))
done
probe_detail control_socket_mode "$(sudo -n stat -f %Lp "$sock" 2>/dev/null || echo missing)"
cc=$(client id)
probe_detail control_client_result "$cc"
settled_after=yes
settle control_settled_after || settled_after=no
act_after=$(activations)
probe_detail control_new_daemon_pids "$((act_after - act_before))"
control=failed
case $cc in
  *connect=error*errno=13*) if [ "$act_after" = "$act_before" ] && [ "$settled_before" = yes ] && [ "$settled_after" = yes ]; then control=ok; fi ;;
esac

# --- clean V1, then V2 on a clean state ------------------------------------------------------
sudo -n launchctl bootout "system/$label" >/dev/null 2>&1 || true
sudo -n rm -f "$plist" "$sock"
sudo -n rm -rf "$H" "$A"
sudo -n pkgutil --forget "$pkg_id_v1" >/dev/null 2>&1 || true
probe_detail clean_v1_home_gone "$(if [ -e "$H" ]; then echo no; else echo yes; fi)"

run_installer "$work/v2.pkg"
v2_rc=$INST_RC
probe_detail v2_installer_rc "$v2_rc"
probe_detail v2_installer_last "$INST_LAST"
record_folders v2_after
probe_detail v2_leaf_has_bundle "$(if sudo -n test -d "$H/.installer/probe-app/LpProbeM3-src.app"; then echo yes; else echo no; fi)"
v2_unchanged=no
if [ "$(facts /Library)" = "$before_lib" ] && [ "$(facts "/Library/Application Support")" = "$before_app" ]; then
  v2_unchanged=yes
fi
v2_perms=no
if variant_perms_ok; then v2_perms=yes; fi
sudo -n rm -rf "$H"
sudo -n pkgutil --forget "$pkg_id_v2" >/dev/null 2>&1 || true

# --- verdict ---------------------------------------------------------------------------------
a1=no
if [ "$sock_owner" = root ] && [ "$sock_type" = Socket ] && [ "$sock_mode" = 666 ] &&
  [ -n "$pid1" ] && [ "$pid1" = "$pid2" ] && [ "$euid1" = 0 ] && [ "$euid2" = 0 ] &&
  [ "$peer1" = "$user_uid" ] && [ "$peer2" = "$user_uid" ] && [ "$server1" = 0 ] &&
  [ -n "$pid3" ] && [ "$pid3" != "$pid1" ]; then
  a1=yes
fi
a3=no
if [ "$pi_euid" = 0 ] && [ "$v1_rc" -eq 0 ]; then a3=yes; fi
a6=no
if [ "$markers_pi" = "A=b S=a" ] && [ "$sw_reply" = "swap=0 errno=0" ] && [ "$markers_dm" = "A=a S=b" ] &&
  [ "$(fld "$pi" swap_rc)" = 0 ]; then
  a6=yes
fi
a7=no
if [ "$a7_codesign_rc" -eq 0 ] && [ "$exe_path" = "$expected_exe" ]; then a7=yes; fi
qual_v1=no
if [ "$v1_rc" -eq 0 ] && [ "$v1_unchanged" = yes ] && [ "$v1_perms" = yes ]; then qual_v1=yes; fi
qual_v2=no
if [ "$v2_rc" -eq 0 ] && [ "$v2_unchanged" = yes ] && [ "$v2_perms" = yes ]; then qual_v2=yes; fi
chosen=none
if [ "$qual_v2" = yes ]; then chosen=V2; fi
if [ "$qual_v1" = yes ]; then chosen=V1; fi
probe_detail p4_v1_library_unchanged "$v1_unchanged"
probe_detail p4_v2_library_unchanged "$v2_unchanged"
probe_detail p8_v1_modes_ok "$v1_perms"
probe_detail p8_v2_modes_ok "$v2_perms"
probe_detail qualifies_v1 "$qual_v1"
probe_detail qualifies_v2 "$qual_v2"
probe_detail chosen_variant "$chosen"
probe_detail a1 "$a1"
probe_detail a3 "$a3"
probe_detail a6 "$a6"
probe_detail a7 "$a7"

verdict=FAIL
if [ "$a1" = yes ] && [ "$a3" = yes ] && [ "$a6" = yes ] && [ "$a7" = yes ] && [ "$chosen" != none ]; then
  verdict=PASS
fi
probe_finish "$verdict" "$control"
echo "p-m3: recorded (requested $verdict, control $control)"
