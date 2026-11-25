#!/usr/bin/env bash
# Builds the lunepack runtime for a Linux or macOS target (M5-D7, M8-D14). `lunepack pack --runtime
# <path>` places the result beside the app's entry. Run from anywhere; builds from the repo top level.
#
#   scripts/build-runtime.sh <target> [--package <name>] [--out <path>]
#   scripts/build-runtime.sh --print-command <target> [--package <name>]   # print the build command(s), run nothing
#
# --package builds another shipped binary by the same rules and checks (M13 step 14, the release
# build): lunepack-runtime (the default), lunepack-service (static musl on Linux, like the runtime),
# or lunepack-ui on a macOS target only (the UI is not a static binary: on Linux the release build
# makes it with the host's C library, scripts/release/build.sh).
#
# Targets: linux-x86_64, linux-aarch64 (a static musl build), macos-aarch64, macos-x86_64 and
# macos-universal (both slices, joined by `lipo -create`; macOS hosts only).
#
# Linux: needs a C compiler for the musl target (ring's C code goes through it): `musl-gcc` when the
# host has the target's architecture, else `CC_<triple with underscores>`; and `readelf` for the
# check. The musl target must be installed (`rustup target add <triple>`); this script installs
# nothing. The binary is stripped, then checked: an ELF of the target's machine, no PT_INTERP and no
# NEEDED entry (a static binary; a static-pie has ET_DYN, so the type is not the test).
#
# macOS: needs a macOS host (the Apple linker, `lipo`, `otool`) and both Apple targets installed
# (rust-toolchain.toml lists them). The build runs with MACOSX_DEPLOYMENT_TARGET=10.15, which binds
# the x86_64 slice only: the aarch64 slice keeps Rust's own minimum, macOS 11.0, the first release
# for Apple silicon. The binary is stripped, then checked: `lipo -archs` names exactly the target's
# architecture(s), `otool -L` lists system libraries only (/usr/lib, /System/Library), and the
# x86_64 slice's minimum macOS is 10.15. The Apple linker signs an arm64 binary ad hoc
# ("linker-signed") and leaves an x86_64 one unsigned; a slice it left unsigned gets the same kind
# of signature (`codesign -s - -o linker-signed`, no identity), so every slice of the result passes
# `codesign --verify --strict` and an app's own signer replaces it as it replaces the linker's.
#
# CARGO_TARGET_DIR is honoured (default: target/ at the repo root). The script prints the binary's
# size (the first measured build is the D37 baseline, docs/STATE.md). bash 3.2 compatible (D30).
set -euo pipefail

self=${0##*/}

# The lowest macOS the x86_64 slice runs on (M8-D14); the aarch64 slice's minimum is Rust's 11.0.
deployment_target=10.15

usage() {
  echo "usage: $self [--print-command] <linux-x86_64|linux-aarch64|macos-aarch64|macos-x86_64|macos-universal> [--package <lunepack-runtime|lunepack-service|lunepack-ui>] [--out <path>]" >&2
  echo "  macOS builds set MACOSX_DEPLOYMENT_TARGET=$deployment_target, which binds the x86_64 slice only;" >&2
  echo "  the aarch64 slice keeps Rust's 11.0 minimum." >&2
}

die() {
  echo "$self: $*" >&2
  exit 1
}

print_only=0
out=
have_out=0
target=
package=
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
    --package)
      if [ -n "$package" ] || [ "$#" -lt 2 ] || [ -z "$2" ]; then
        usage
        exit 2
      fi
      package=$2
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
case ${package:=lunepack-runtime} in
  lunepack-runtime | lunepack-service | lunepack-ui) ;;
  *)
    echo "$self: unknown package (only lunepack-runtime, lunepack-service and lunepack-ui are built here)" >&2
    usage
    exit 2
    ;;
esac

kind=linux
triples=()
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
  macos-aarch64)
    kind=macos
    triples=(aarch64-apple-darwin)
    want_archs=arm64
    ;;
  macos-x86_64)
    kind=macos
    triples=(x86_64-apple-darwin)
    want_archs=x86_64
    ;;
  macos-universal)
    kind=macos
    triples=(aarch64-apple-darwin x86_64-apple-darwin)
    want_archs='arm64 x86_64'
    ;;
  *)
    echo "$self: unknown target (only linux-x86_64, linux-aarch64, macos-aarch64, macos-x86_64 and macos-universal are built here)" >&2
    usage
    exit 2
    ;;
esac

if [ "$package" = lunepack-ui ] && [ "$kind" != macos ]; then
  echo "$self: lunepack-ui is built for macOS targets only here (on Linux it is not a static binary; scripts/release/build.sh builds it)" >&2
  usage
  exit 2
fi

target_dir=${CARGO_TARGET_DIR:-target}
build_args=(build --locked --release -p "$package" --config profile.release.strip=true)

if [ "$kind" = macos ]; then
  universal_bin=$target_dir/universal-apple-darwin/release/$package
  if [ "$print_only" -eq 1 ]; then
    for t in "${triples[@]}"; do
      echo "MACOSX_DEPLOYMENT_TARGET=$deployment_target cargo build --locked --release -p $package --target $t --config profile.release.strip=true"
    done
    if [ "$target" = macos-universal ]; then
      echo "lipo -create -output $universal_bin $target_dir/aarch64-apple-darwin/release/$package $target_dir/x86_64-apple-darwin/release/$package"
    fi
    exit 0
  fi
else
  cmd=(cargo build --locked --release -p "$package" --target "$triple" --config profile.release.strip=true)
  if [ "$print_only" -eq 1 ]; then
    echo "${cmd[*]}"
    exit 0
  fi
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

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac

if [ "$kind" = macos ]; then
  [ "$(uname -s)" = Darwin ] || die "macOS targets are built on a macOS host only (the Apple linker, lipo and otool are needed)"
  for tool in lipo otool codesign; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH (the Xcode command line tools); the check cannot run"
  done
  cd "$here/.."
  for t in "${triples[@]}"; do
    MACOSX_DEPLOYMENT_TARGET=$deployment_target cargo "${build_args[@]}" --target "$t"
    slice=$target_dir/$t/release/$package
    [ -f "$slice" ] || die "the build left no $slice"
    # A slice the linker left unsigned (x86_64) gets the linker's kind of ad-hoc signature; any
    # other verification failure is an error.
    if ! verify_out=$(LC_ALL=C codesign --verify "$slice" 2>&1); then
      case $verify_out in
        *"not signed at all"*) LC_ALL=C codesign -s - -o linker-signed "$slice" || die "codesign could not sign $slice ad hoc" ;;
        *) die "codesign --verify failed on $slice: $verify_out" ;;
      esac
    fi
  done
  if [ "$target" = macos-universal ]; then
    mkdir -p "${universal_bin%/*}"
    lipo -create -output "$universal_bin" \
      "$target_dir/aarch64-apple-darwin/release/$package" \
      "$target_dir/x86_64-apple-darwin/release/$package"
    bin=$universal_bin
  else
    bin=$target_dir/${triples[0]}/release/$package
  fi
  [ -f "$bin" ] || die "the build left no $bin"

  # The Mach-O check fails closed: a tool that prints nothing recognisable is a failure.
  archs=$(LC_ALL=C lipo -archs "$bin") || die "$bin is not a Mach-O file"
  have_archs=$(printf '%s\n' "$archs" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ')
  want_sorted=$(printf '%s\n' "$want_archs" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ')
  [ "$have_archs" = "$want_sorted" ] || die "$bin holds the architectures [${archs}], not [$want_archs]"
  libs=$(LC_ALL=C otool -L "$bin") || die "otool -L failed on $bin"
  tab=$(printf '\t')
  count=0
  while IFS= read -r line; do
    case $line in
      "$tab"*)
        lib=${line#"$tab"}
        case $lib in
          /usr/lib/* | /System/Library/*) count=$((count + 1)) ;;
          *) die "$bin links ${lib%% (*}: only /usr/lib and /System/Library libraries are allowed" ;;
        esac
        ;;
    esac
  done <<<"$libs"
  [ "$count" -gt 0 ] || die "otool -L listed no libraries for $bin (not a Mach-O the check can read)"
  # The x86_64 slice's minimum macOS; the aarch64 slice is reported, not held to a number.
  minos_report=
  for a in $archs; do
    minos=$(LC_ALL=C otool -arch "$a" -l "$bin" | awk '
      /LC_BUILD_VERSION/ { want = "minos" }
      /LC_VERSION_MIN_MACOSX/ { want = "version" }
      want != "" && $1 == want { print $2; exit }') || die "otool -l failed on $bin"
    [ -n "$minos" ] || die "no minimum macOS version in the $a slice of $bin"
    if [ "$a" = x86_64 ] && [ "$minos" != "$deployment_target" ]; then
      die "the x86_64 slice of $bin needs macOS $minos, not $deployment_target"
    fi
    minos_report="$minos_report $a=$minos"
  done
  LC_ALL=C codesign --verify --strict --all-architectures "$bin" >/dev/null 2>&1 || die "$bin does not pass codesign --verify --strict on every slice"

  if [ "$have_out" -eq 1 ]; then
    cp "$bin" "$out"
    echo "copied to: $out"
  fi
  size=$(wc -c <"$bin")
  echo "built: $bin"
  echo "macho: yes (${archs}; system libraries only)"
  echo "minos:${minos_report}"
  echo "signature: ad hoc on every slice (codesign --verify --strict passes)"
  echo "size: ${size//[[:space:]]/} bytes"
  exit 0
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

cd "$here/.."
"${cmd[@]}"
bin=$target_dir/$triple/release/$package
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
