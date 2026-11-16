#!/usr/bin/env bash
# Builds the static lunepack runtime for a Linux target (M5-D7). `lunepack pack --runtime <path>`
# places the result beside the app's entry. Run from anywhere; builds from the repo top level.
#
#   scripts/build-runtime.sh <linux-x86_64|linux-aarch64> [--out <path>]
#   scripts/build-runtime.sh --print-command <target>   # print the build command, run nothing
#
# Needs a C compiler for the musl target (ring's C code goes through it): `musl-gcc` when the host
# has the target's architecture, else `CC_<triple with underscores>`; and `readelf` for the check.
# CARGO_TARGET_DIR is honoured (default: target/ at the repo root).
# The musl target must be installed (`rustup target add <triple>`); this script installs nothing.
# The binary is stripped, then checked: an ELF of the target's machine, no PT_INTERP and no NEEDED
# entry (a static binary; a static-pie has ET_DYN, so the type is not the test). It prints the size
# (the first measured build is the D37 baseline, docs/STATE.md). bash 3.2 compatible (D30).
set -euo pipefail

self=${0##*/}

usage() {
  echo "usage: $self [--print-command] <linux-x86_64|linux-aarch64> [--out <path>]" >&2
}

die() {
  echo "$self: $*" >&2
  exit 1
}

print_only=0
out=
have_out=0
target=
while [ "$#" -gt 0 ]; do
  case $1 in
    -h | --help)
      usage
      exit 0
      ;;
    --print-command)
      if [ "$print_only" -eq 1 ]; then
        usage
        exit 2
      fi
      print_only=1
      shift
      ;;
    --out)
      if [ "$have_out" -eq 1 ] || [ "$#" -lt 2 ] || [ -z "$2" ]; then
        usage
        exit 2
      fi
      have_out=1
      out=$2
      shift 2
      ;;
    *)
      if [ -n "$target" ]; then
        usage
        exit 2
      fi
      target=$1
      shift
      ;;
  esac
done
if [ -z "$target" ]; then
  usage
  exit 2
fi

case $target in
  linux-x86_64)
    triple=x86_64-unknown-linux-musl
    arch=x86_64
    machine='Advanced Micro Devices X86-64'
    ;;
  linux-aarch64)
    triple=aarch64-unknown-linux-musl
    arch=aarch64
    machine='AArch64'
    ;;
  *)
    echo "$self: unknown target (only linux-x86_64 and linux-aarch64 are built here)" >&2
    usage
    exit 2
    ;;
esac

cmd=(cargo build --locked --release -p lunepack-runtime --target "$triple" --config profile.release.strip=true)
if [ "$print_only" -eq 1 ]; then
  echo "${cmd[*]}"
  exit 0
fi

# An --out path is taken relative to the caller's directory, before the script changes into the
# repo root; its parent must already exist (nothing is created for the caller).
if [ "$have_out" -eq 1 ]; then
  case $out in
    /*) ;;
    *) out=$PWD/$out ;;
  esac
  case $out in
    */) die "--out names a directory; give a file path" ;;
  esac
  [ -d "${out%/*}" ] || die "--out: the parent directory does not exist"
fi

# The C compiler for the musl target: CC_<triple> if set, else musl-gcc when the host has the
# target's architecture (musl-gcc compiles for its own host only).
cc_var=CC_${triple//-/_}
cc_val=${!cc_var:-}
if [ -n "$cc_val" ]; then
  command -v "${cc_val%% *}" >/dev/null 2>&1 || die "$cc_var names a compiler that is not on PATH"
else
  host=$(uname -m)
  [ "$host" = arm64 ] && host=aarch64
  if [ "$host" != "$arch" ]; then
    die "this host is $host: set $cc_var to a cross compiler for $triple (musl-gcc builds for its own host only)"
  fi
  command -v musl-gcc >/dev/null 2>&1 || die "musl-gcc is not on PATH (apt: musl-tools), and $cc_var is not set"
fi
command -v readelf >/dev/null 2>&1 || die "readelf is not on PATH (apt: binutils); the static check cannot run"

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
cd "$here/.."
"${cmd[@]}"
bin=${CARGO_TARGET_DIR:-target}/$triple/release/lunepack-runtime
[ -f "$bin" ] || die "the build left no $bin"

# The static check fails closed: a readelf that prints nothing recognisable is a failure.
hdr=$(LC_ALL=C readelf -hW "$bin") || die "$bin is not an ELF file"
case $hdr in
  *"Machine:"*"$machine"*) ;;
  *) die "$bin is not an ELF for $triple (machine is not $machine)" ;;
esac
prog=$(LC_ALL=C readelf -lW "$bin") || die "readelf -l failed on $bin"
case $prog in
  *"Program Headers:"*) ;;
  *) die "readelf -l printed no program headers for $bin" ;;
esac
case $prog in
  *INTERP*) die "$bin has a program interpreter (PT_INTERP): it is dynamically linked" ;;
esac
dyn=$(LC_ALL=C readelf -dW "$bin" 2>/dev/null || true)
case $dyn in
  *"(NEEDED)"*) die "$bin has NEEDED entries: it is dynamically linked" ;;
esac

if [ "$have_out" -eq 1 ]; then
  cp "$bin" "$out"
  echo "copied to: $out"
fi
size=$(wc -c <"$bin")
echo "built: $bin"
echo "static: yes ($triple, no PT_INTERP, no NEEDED)"
echo "size: ${size//[[:space:]]/} bytes"
