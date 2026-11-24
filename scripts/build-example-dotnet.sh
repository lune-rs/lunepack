#!/usr/bin/env bash
# Publishes the .NET example app (examples/dotnet) self-contained for a lunepack target id (M13-D13).
# The output is a folder of about 190 files, not single-file and not trimmed, with no debug files.
# Run from anywhere.
#
#   scripts/build-example-dotnet.sh <target> <out-dir> [--macos-bundle <dir>]
#   scripts/build-example-dotnet.sh --print-command <target> <out-dir> [--macos-bundle <dir>]
#                                    # print the build command, run nothing
#
# Targets and the .NET runtime identifiers they publish for (the one table, below):
#   linux-x86_64 -> linux-x64      linux-aarch64 -> linux-arm64      windows-x86_64 -> win-x64
#   macos-aarch64 -> osx-arm64     macos-x86_64 -> osx-x64
# `macos-universal` is refused: a self-contained .NET app is built per architecture, so on macOS the
# app is packed for macos-aarch64 or macos-x86_64, with a thin runtime.
#
# <out-dir> must be absent or empty. The entry is `Example` (`Example.exe` on Windows), beside
# `lunepack-runtime` once packed.
#
# --macos-bundle <dir> (macos-* targets only; <dir> must be absent) also builds the app bundle that
# `lunepack pack` takes: the host alone in Contents/MacOS, every other file under Contents/Resources/app
# (a signature of a file that is not Mach-O lives in an extended attribute, which a pack does not
# carry), and an Info.plist. The host's path to the managed files is written by the SDK's own
# CreateAppHost task, from the project file. <dir> may lie inside <out-dir>.
#
# Needs the .NET SDK that examples/dotnet/global.json names (the pin is the SDK; the project has no
# package reference) and network access to nuget.org for the runtime pack of the target. bash 3.2
# compatible (D30).
set -euo pipefail

self=${0##*/}
here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
repo=$(cd "$here/.." && pwd)
project_dir=$repo/examples/dotnet

# The assembly name of examples/dotnet/Example.csproj: the host's file name.
app=Example

usage() {
  echo "usage: $self [--print-command] <target> <out-dir> [--macos-bundle <dir>]" >&2
  echo "  targets: linux-x86_64 linux-aarch64 windows-x86_64 macos-aarch64 macos-x86_64" >&2
  echo "  --macos-bundle (macos-* targets): also build the app bundle <dir>, the host alone in Contents/MacOS" >&2
}

die() {
  echo "$self: $*" >&2
  exit 1
}

# The one table: lunepack target id -> .NET runtime identifier.
rid_of() {
  case $1 in
    linux-x86_64) echo linux-x64 ;;
    linux-aarch64) echo linux-arm64 ;;
    windows-x86_64) echo win-x64 ;;
    macos-aarch64) echo osx-arm64 ;;
    macos-x86_64) echo osx-x64 ;;
    *) return 1 ;;
  esac
}

abspath() {
  case $1 in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$PWD/$1" ;;
  esac
}

print_only=0
target=
out=
have_out=0
bundle=
have_bundle=0
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
    --macos-bundle)
      if [ "$have_bundle" -eq 1 ] || [ "$#" -lt 2 ] || [ -z "$2" ]; then
        usage
        exit 2
      fi
      have_bundle=1
      bundle=$2
      shift 2
      ;;
    *)
      if [ -z "$target" ]; then
        target=$1
      elif [ "$have_out" -eq 0 ]; then
        have_out=1
        out=$1
      else
        usage
        exit 2
      fi
      shift
      ;;
  esac
done

if [ -z "$target" ] || [ "$have_out" -eq 0 ] || [ -z "$out" ]; then
  usage
  exit 2
fi
if [ "$target" = macos-universal ]; then
  echo "$self: macos-universal is not built: a self-contained .NET app is built per architecture;" >&2
  echo "  build macos-aarch64 or macos-x86_64 and pack the app for that target with a thin runtime" >&2
  exit 2
fi
rid=$(rid_of "$target") || {
  echo "$self: unknown target '$target'" >&2
  usage
  exit 2
}
if [ "$have_bundle" -eq 1 ]; then
  case $target in
    macos-*) ;;
    *)
      echo "$self: --macos-bundle needs a macos-* target" >&2
      usage
      exit 2
      ;;
  esac
fi

out=$(abspath "$out")
host=$app
case $target in
  windows-*) host=$app.exe ;;
esac

if [ -e "$out" ] && { [ ! -d "$out" ] || [ -n "$(ls -A "$out")" ]; }; then
  die "the output directory '$out' exists and is not empty; use a new or empty one"
fi
if [ "$have_bundle" -eq 1 ]; then
  bundle=$(abspath "$bundle")
  if [ -e "$bundle" ]; then
    die "the bundle '$bundle' exists; use a new path"
  fi
  case $bundle in
    "$out") die "the bundle cannot be the output directory itself" ;;
  esac
fi

args=(publish "$project_dir/$app.csproj" -c Release -r "$rid" --self-contained -o "$out" --nologo)
if [ "$have_bundle" -eq 1 ]; then
  args+=("-p:MacBundleHost=$bundle/Contents/MacOS/$app")
fi

if [ "$print_only" -eq 1 ]; then
  printf 'cd %q &&' "$project_dir"
  printf ' dotnet'
  printf ' %q' "${args[@]}"
  printf '\n'
  if [ "$have_bundle" -eq 1 ]; then
    echo "# then: every file of the output but $app moves under $bundle/Contents/Resources/app, and an Info.plist is written"
  fi
  exit 0
fi

command -v dotnet >/dev/null 2>&1 || die "dotnet is not on PATH; install the SDK named by examples/dotnet/global.json"

# `dotnet` reads global.json from the working directory, not from the project's.
cd "$project_dir"
if [ "$have_bundle" -eq 1 ]; then
  mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources/app"
fi
dotnet "${args[@]}"

[ -f "$out/$host" ] || die "the publish did not write $out/$host"
if [ -n "$(find "$out" -name '*.pdb' -print -quit)" ]; then
  die "the publish wrote a .pdb file under $out"
fi

if [ "$have_bundle" -eq 1 ]; then
  [ -f "$bundle/Contents/MacOS/$app" ] || die "the publish did not write the bundle's host"
  # Every file of the publish but the flat host goes beside the app path the bundle's host names.
  # Only the entries the publish wrote are copied: the bundle itself may lie inside <out-dir>.
  for entry in "$out"/* "$out"/.[!.]*; do
    [ -e "$entry" ] || continue
    [ "$entry" = "$out/$host" ] && continue
    [ "$entry" = "$bundle" ] && continue
    cp -R "$entry" "$bundle/Contents/Resources/app/"
  done
  cat >"$bundle/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$app</string>
<key>CFBundleIdentifier</key><string>org.lunepack.example.dotnet</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>$app</string>
</dict></plist>
EOF
  [ -f "$bundle/Contents/Resources/app/$app.dll" ] || die "the bundle holds no $app.dll under Contents/Resources/app"
fi

if [ "$have_bundle" -eq 1 ]; then
  count=$(find "$out" -type f ! -path "$bundle/*" | wc -l | tr -d ' ')
else
  count=$(find "$out" -type f | wc -l | tr -d ' ')
fi
echo "$self: $target ($rid): $count files in $out"
if [ "$have_bundle" -eq 1 ]; then
  echo "$self: bundle $bundle"
fi
