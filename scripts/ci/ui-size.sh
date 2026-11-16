#!/usr/bin/env bash
# The size report of the UI binary (M6, D37 (b)): its raw size and the frame length `lunepack pack`
# chooses for it, read from the packager's own output on a one-file tree. It reports and never fails
# on a size; it fails (fail closed) only when it cannot read one.
#
#   scripts/ci/ui-size.sh <lunepack-ui> <lunepack> [summary-file]
#
# The throw-away signing keys are generated here, in a temporary directory that is removed on exit,
# and never leave it. The report goes to stdout and, when a summary file is given or GITHUB_STEP_SUMMARY
# is set, is appended to it as a Markdown table row. bash 3.2 compatible.
set -euo pipefail

usage() {
  echo "usage: scripts/ci/ui-size.sh <lunepack-ui> <lunepack> [summary-file]" >&2
}

die() {
  echo "ui-size: $*" >&2
  exit 1
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  usage
  exit 2
fi
ui=$1
cli=$2
summary=${3:-${GITHUB_STEP_SUMMARY:-}}
[ -f "$ui" ] || die "the UI binary is not a file: $ui"
[ -f "$cli" ] || [ -x "$cli" ] || die "the lunepack command is not a file: $cli"

# The packer's target for this host (the same names `lunepack pack --target` takes).
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=macos-aarch64 ;;
  Darwin-x86_64) target=macos-x86_64 ;;
  Linux-x86_64) target=linux-x86_64 ;;
  Linux-aarch64 | Linux-arm64) target=linux-aarch64 ;;
  MINGW* | MSYS* | CYGWIN*) target=windows-x86_64 ;;
  *) die "no pack target for $(uname -s) $(uname -m)" ;;
esac

# The raw size, in bytes, read with wc: an empty or unreadable file is an error.
raw=$(wc -c <"$ui" | tr -d ' ')
case $raw in
  '' | *[!0-9]*) die "could not read the size of $ui" ;;
esac
[ "$raw" -gt 0 ] || die "the UI binary is empty: $ui"

work=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-ui-size.XXXXXX")
cleanup() {
  # Only the directory created above.
  rm -rf "$work"
}
trap cleanup EXIT

mkdir "$work/tree" "$work/release"
cp "$ui" "$work/tree/lunepack-ui"
# Absolute paths for what is used after the change of directory.
abs() {
  case $1 in
    /* | [A-Za-z]:*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$PWD" "$1" ;;
  esac
}
cli=$(abs "$cli")
if [ -n "$summary" ]; then summary=$(abs "$summary"); fi
cd "$work"

# A root and a release key made for this run; `keys gen` writes the files and prints the public
# halves, which is all that is read from its output.
root_pub=$("$cli" keys gen root.sk | sed -n 's/^public: //p')
release_pub=$("$cli" keys gen release.sk | sed -n 's/^public: //p')
[ -n "$root_pub" ] && [ -n "$release_pub" ] || die "could not read the public keys from the packager's output"
"$cli" init --app-id org.example.size --root-key "$root_pub" >/dev/null
"$cli" keys set --release-dir release --release-key "$release_pub" --sign file:root.sk >/dev/null
out=$("$cli" pack --input tree --version 1.0.0 --target "$target" --release-dir release --sign file:release.sk)

# "totals: 1 file(s), <input> input bytes, <pack> pack bytes": one file, one frame, so the pack's
# size is the frame length the packager chose; "codec <name>: 1" names the codec it chose.
totals=$(printf '%s\n' "$out" | sed -n 's/^totals: .*, \([0-9][0-9]*\) input bytes, \([0-9][0-9]*\) pack bytes$/\1 \2/p')
[ -n "$totals" ] || die "could not read the totals line of the packager's output"
input_bytes=${totals% *}
frame=${totals#* }
codec=$(printf '%s\n' "$out" | sed -n 's/^codec \(.*\): 1$/\1/p' | head -n 1)
[ -n "$codec" ] || codec=unknown
[ "$input_bytes" = "$raw" ] || die "the packager saw $input_bytes bytes, the file has $raw"
[ "$frame" -gt 0 ] || die "the packager reported an empty frame"

line="| $target | $raw | $frame | $codec |"
echo "ui-size: $target: raw $raw bytes, frame $frame bytes ($codec)"
if [ -n "$summary" ]; then
  {
    echo "### lunepack-ui size"
    echo
    echo "| target | raw bytes | frame bytes (lunepack pack) | codec |"
    echo "| --- | --- | --- | --- |"
    echo "$line"
    echo
  } >>"$summary"
fi
