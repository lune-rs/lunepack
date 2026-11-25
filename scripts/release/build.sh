#!/usr/bin/env bash
# Builds the prebuilt binaries of one release target (M13 step 14, M13-D19 as revised) into <outdir>,
# each named lunepack-<kind>-<version>-<target>. Windows: scripts/release/build.ps1.
#
#   scripts/release/build.sh <linux-x86_64|linux-aarch64|macos-universal> <outdir>
#
#   linux-*          runtime and service: static musl, by scripts/build-runtime.sh's rules and checks;
#                    ui: the host's C library (built on the oldest hosted Ubuntu image, so it runs on
#                    every newer one), an ELF of the target's machine. The host must be the target's
#                    architecture (no cross build).
#   macos-universal  runtime, service and ui: universal, by scripts/build-runtime.sh's rules and checks
#                    (both slices, system libraries only, the x86_64 minimum, an ad-hoc signature on
#                    every slice); then for each kind the two thin files cut with `lipo -thin`,
#                    released as macos-aarch64 and macos-x86_64. Every file passes
#                    `codesign --verify --strict` and the header check `pack` applies to its target
#                    (a thin Mach-O of the target's CPU, or a fat one of both for universal).
#
# <outdir> is created when absent and must be empty. LUNEPACK_BUILD_ID must not be set: the released
# binaries of one version are one build, so the version-based build id is exact (M13 P6).
# bash 3.2 compatible (D30).
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() {
  echo "usage: ${0##*/} <linux-x86_64|linux-aarch64|macos-universal> <outdir>" >&2
}

[ "$#" -eq 2 ] && [ -n "$1" ] && [ -n "$2" ] || {
  usage
  exit 2
}
target=$1
outdir=$2

if [ -n "${LUNEPACK_BUILD_ID+set}" ]; then
  rel_die "LUNEPACK_BUILD_ID must not be set for a release build (it is set in this environment)"
fi

case $target in
  linux-x86_64) gnu=x86_64-unknown-linux-gnu machine='Advanced Micro Devices X86-64' arch=x86_64 ;;
  linux-aarch64) gnu=aarch64-unknown-linux-gnu machine='AArch64' arch=aarch64 ;;
  macos-universal) ;;
  *)
    echo "${0##*/}: unknown target (windows-x86_64 is built by build.ps1)" >&2
    usage
    exit 2
    ;;
esac

case $outdir in
  /*) ;;
  *) outdir=$PWD/$outdir ;;
esac
mkdir -p "$outdir"
[ -z "$(ls -A "$outdir")" ] || rel_die "the output directory is not empty"

cd "$here/../.."
version=$(rel_version "$PWD")
build_runtime=$PWD/scripts/build-runtime.sh

# macho_header_ok <file> <cpu: arm64|x86_64|fat>: the check `pack` applies to a macOS runtime
# (core pack.rs check_macho_runtime): a thin 64-bit little-endian Mach-O of the CPU, or a fat file
# holding both slices.
macho_header_ok() {
  local magic cpu
  magic=$(od -An -tx1 -N4 "$1" | tr -d ' \n')
  case $2 in
    fat)
      [ "$magic" = cafebabe ] || return 1
      [ "$(LC_ALL=C lipo -archs "$1" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ')" = "arm64 x86_64 " ]
      ;;
    *)
      [ "$magic" = cffaedfe ] || return 1
      cpu=$(od -An -tx1 -j4 -N4 "$1" | tr -d ' \n')
      case $2 in
        arm64) [ "$cpu" = 0c000001 ] ;;
        x86_64) [ "$cpu" = 07000001 ] ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

if [ "$target" = macos-universal ]; then
  [ "$(uname -s)" = Darwin ] || rel_die "macos-universal is built on a macOS host only"
  rel_need lipo codesign od
  for kind in runtime service ui; do
    u=$outdir/$(rel_asset "$kind" "$version" macos-universal)
    "$build_runtime" macos-universal --package "lunepack-$kind" --out "$u"
    a=$outdir/$(rel_asset "$kind" "$version" macos-aarch64)
    x=$outdir/$(rel_asset "$kind" "$version" macos-x86_64)
    lipo "$u" -thin arm64 -output "$a" || rel_die "lipo -thin arm64 failed on $u"
    lipo "$u" -thin x86_64 -output "$x" || rel_die "lipo -thin x86_64 failed on $u"
    for pair in "$u:fat" "$a:arm64" "$x:x86_64"; do
      f=${pair%:*}
      LC_ALL=C codesign --verify --strict --all-architectures "$f" || rel_die "${f##*/} does not pass codesign --verify --strict"
      macho_header_ok "$f" "${pair##*:}" || rel_die "${f##*/} is not the Mach-O pack accepts for its target (${pair##*:})"
      echo "checked: ${f##*/} (codesign --verify --strict, Mach-O ${pair##*:})"
    done
  done
else
  rel_need readelf
  host=$(uname -m)
  [ "$host" = arm64 ] && host=aarch64
  [ "$host" = "$arch" ] || rel_die "this host is $host: $target is built on a host of its own architecture"
  for kind in runtime service; do
    "$build_runtime" "$target" --package "lunepack-$kind" --out "$outdir/$(rel_asset "$kind" "$version" "$target")"
  done
  cargo build --locked --release -p lunepack-ui --target "$gnu" --config profile.release.strip=true
  ui=${CARGO_TARGET_DIR:-target}/$gnu/release/lunepack-ui
  [ -f "$ui" ] || rel_die "the build left no $ui"
  hdr=$(LC_ALL=C readelf -hW "$ui") || rel_die "$ui is not an ELF file"
  case $hdr in
    *"Machine:"*"$machine"*) ;;
    *) rel_die "$ui is not an ELF for $target (machine is not $machine)" ;;
  esac
  cp "$ui" "$outdir/$(rel_asset ui "$version" "$target")"
  echo "checked: $(rel_asset ui "$version" "$target") (ELF, $machine)"
fi

echo "built in $outdir:"
for f in "$outdir"/*; do
  echo "  ${f##*/} $(rel_size "$f") bytes"
done
