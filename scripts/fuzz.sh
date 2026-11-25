#!/usr/bin/env bash
# The fuzz campaign (M13-D9): libFuzzer over every target of fuzz/, in a pinned Docker image.
# It is not part of the gate (scripts/gate.sh); the weekly workflow runs it (.github/workflows/weekly.yml).
#
#   scripts/fuzz.sh [--docker | --inside] [--seconds N] [--list] [target...]
#
#   --docker       run in a Docker container (the default; the usual way)
#   --inside       run here: the container's own entry and CI. Refuses outside a container or CI,
#                  and as root. Needs cargo-fuzz and the nightly toolchain of scripts/fuzz.Dockerfile.
#   --seconds N    libFuzzer's -max_total_time for each target (default 600; M13-D9: 600 by hand,
#                  300 weekly)
#   --list         print the target names, one per line, and exit (no Docker, no build)
#   target...      only these targets (default: all)
#
# The target list is derived, never typed: the [[bin]] names of fuzz/Cargo.toml. They must equal the
# core's HARNESSES (crates/lunepack-core/src/fuzz.rs) plus the codec crate's
# (crates/lunepack-codec-lzma/src/fuzz.rs), and fuzz/fuzz_targets/*.rs must name the same set; a
# difference fails the script (--list included), so no target can be left out silently.
#
# Per target: the working corpus is fuzz/corpus/<target> (ignored by git), seeded from
# fuzz/seeds/<target> (read only); crash inputs land in fuzz/artifacts/<target>. One line per target:
#   fuzz: <target> runs=<executed units> corpus=<files> crashes=<new crash, timeout, oom and leak files>
# The exit status is non-zero when any target crashed or could not run. No sanitizer is switched off
# and no target is skipped to make a run pass; a crash is kept, reported and fixed (a committed seed
# plus the fix), never ignored. A single input that takes more than 30 s is reported as a hang.
#
# The Docker mode builds the image `lunepack-rs-fuzz:<hash>` from scripts/fuzz.Dockerfile (once per
# Dockerfile change), runs `docker run --rm --init` with the worktree read-only, as the image's
# unprivileged user `fuzz`, the corpus and artifacts folders of the worktree mounted writable, and
# its build output in two named volumes of its own (lunepack-rs-fuzz-target, lunepack-rs-fuzz-cargo).
# It never prunes and never touches other containers, images or volumes. bash 3.2 compatible.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

usage() {
  echo "usage: scripts/fuzz.sh [--docker | --inside] [--seconds N] [--list] [target...]" >&2
}

die() {
  echo "fuzz: $*" >&2
  exit 1
}

mode=
seconds=600
list=0
targets=
while [ "$#" -gt 0 ]; do
  case $1 in
    --docker | --inside)
      [ -z "$mode" ] || [ "$mode" = "${1#--}" ] || {
        usage
        exit 2
      }
      mode=${1#--}
      shift
      ;;
    --seconds)
      [ "$#" -ge 2 ] || {
        usage
        exit 2
      }
      case $2 in
        '' | *[!0-9]* | 0*)
          usage
          exit 2
          ;;
      esac
      [ "${#2}" -le 6 ] || {
        usage
        exit 2
      }
      seconds=$2
      shift 2
      ;;
    --list)
      list=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage
      exit 2
      ;;
    *)
      targets="$targets $1"
      shift
      ;;
  esac
done
[ -n "$mode" ] || mode=docker

# --- the target list --------------------------------------------------------------------------

# harness_names <file>: the names in the `HARNESSES` table of a fuzz.rs, one per line (the table
# runs from its `pub const HARNESSES` line to the first line that ends with `];`).
harness_names() {
  awk '
    /pub const HARNESSES/ { on = 1 }
    on { print }
    on && /\];[[:space:]]*$/ { exit }
  ' "$1" | { grep -o '("[a-z0-9_]*",' || true; } | sed 's/^("//; s/",$//'
}

# bin_names: the [[bin]] names of fuzz/Cargo.toml.
bin_names() {
  awk '
    /^\[/ { bin = ($0 == "[[bin]]") }
    bin && /^name[[:space:]]*=/ { gsub(/^name[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, ""); print }
  ' fuzz/Cargo.toml
}

# file_names: the stems of fuzz/fuzz_targets/*.rs.
file_names() {
  local f
  for f in fuzz/fuzz_targets/*.rs; do
    [ -f "$f" ] || continue
    f=${f##*/}
    echo "${f%.rs}"
  done
}

sorted() { LC_ALL=C sort -u; }

[ -f fuzz/Cargo.toml ] || die "no fuzz/Cargo.toml"
core_names=$(harness_names crates/lunepack-core/src/fuzz.rs | sorted)
codec_names=$(harness_names crates/lunepack-codec-lzma/src/fuzz.rs | sorted)
[ -n "$core_names" ] || die "no harness table found in crates/lunepack-core/src/fuzz.rs"
[ -n "$codec_names" ] || die "no harness table found in crates/lunepack-codec-lzma/src/fuzz.rs"
want=$(printf '%s\n%s\n' "$core_names" "$codec_names" | sorted)
bins=$(bin_names | sorted)
files=$(file_names | sorted)
mismatch=0
if [ "$bins" != "$want" ]; then
  echo "fuzz: the [[bin]] names of fuzz/Cargo.toml are not the harnesses of the core plus the codec crate:" >&2
  diff <(printf '%s\n' "$want") <(printf '%s\n' "$bins") | sed -n 's/^< \(.*\)/  harness without a [[bin]]: \1/p; s/^> \(.*\)/  [[bin]] without a harness: \1/p' >&2 || true
  mismatch=1
fi
if [ "$files" != "$want" ]; then
  echo "fuzz: fuzz/fuzz_targets/*.rs are not the harnesses of the core plus the codec crate:" >&2
  diff <(printf '%s\n' "$want") <(printf '%s\n' "$files") | sed -n 's/^< \(.*\)/  harness without a target file: \1/p; s/^> \(.*\)/  target file without a harness: \1/p' >&2 || true
  mismatch=1
fi
[ "$mismatch" -eq 0 ] || exit 1

if [ "$list" -eq 1 ]; then
  printf '%s\n' "$want"
  exit 0
fi

selected=
if [ -n "$targets" ]; then
  for t in $targets; do
    printf '%s\n' "$want" | grep -qx -- "$t" || {
      echo "fuzz: no such target: $t" >&2
      usage
      exit 2
    }
    selected="$selected $t"
  done
else
  selected=$(printf '%s\n' "$want" | tr '\n' ' ')
fi

# --- docker -----------------------------------------------------------------------------------
if [ "$mode" = docker ]; then
  command -v docker >/dev/null 2>&1 || die "docker is not installed"
  docker info >/dev/null 2>&1 || die "the Docker daemon is not running"
  dockerfile=scripts/fuzz.Dockerfile
  if command -v shasum >/dev/null 2>&1; then
    hash=$(shasum -a 256 "$dockerfile" | cut -c 1-12)
  else
    hash=$(sha256sum "$dockerfile" | cut -c 1-12)
  fi
  image=lunepack-rs-fuzz:$hash
  if docker image inspect "$image" >/dev/null 2>&1; then
    echo "fuzz: using docker image $image"
  else
    echo "fuzz: building docker image $image from $dockerfile"
    docker build --quiet -t "$image" - <"$dockerfile" >/dev/null
  fi
  # The two folders the container writes in: created here, open to the container's user (uid 1000),
  # whoever owns the checkout.
  mkdir -p fuzz/corpus fuzz/artifacts
  chmod a+rwx fuzz/corpus fuzz/artifacts
  # RUSTUP_TOOLCHAIN picks the image's dated nightly over rust-toolchain.toml. No host env is
  # passed, no capabilities, no new privileges.
  # shellcheck disable=SC2086  # $selected is a list of validated target names
  exec docker run --rm --init \
    --name "lunepack-rs-fuzz-$$" \
    --user 1000:1000 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    -v "$top":/src:ro \
    -v "$top/fuzz/corpus":/src/fuzz/corpus \
    -v "$top/fuzz/artifacts":/src/fuzz/artifacts \
    -v lunepack-rs-fuzz-target:/target \
    -v lunepack-rs-fuzz-cargo:/cargo-home \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_HOME=/cargo-home \
    -e RUSTUP_TOOLCHAIN=nightly-2026-11-20 \
    -w /src \
    "$image" \
    ./scripts/fuzz.sh --inside --seconds "$seconds" $selected
fi

# --- inside -----------------------------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "refusing to run: the campaign is Linux only (run scripts/fuzz.sh for Docker)"
if [ ! -e /.dockerenv ] && [ ! -e /run/.containerenv ] && [ -z "${CI:-}" ]; then
  die "refusing to run outside a container or CI (run scripts/fuzz.sh for Docker)"
fi
[ "$(id -u)" != 0 ] || die "refusing to run as root"
command -v cargo-fuzz >/dev/null 2>&1 || die "cargo-fuzz is not installed (it is in the image of scripts/fuzz.Dockerfile)"

log_dir=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-fuzz.XXXXXX")
# shellcheck disable=SC2329  # run by the EXIT trap below
cleanup() {
  # Only the directory created above.
  rm -rf "$log_dir"
}
trap cleanup EXIT

# count_files <dir> [name pattern]: the files directly in a directory.
count_files() {
  if [ -d "$1" ]; then
    find "$1" -maxdepth 1 -type f -name "${2:-*}" | wc -l | tr -d ' '
  else
    echo 0
  fi
}

# count_crashes <dir>: crash, timeout, out-of-memory and leak inputs.
count_crashes() {
  local n=0 p
  for p in 'crash-*' 'timeout-*' 'oom-*' 'leak-*'; do
    n=$((n + $(count_files "$1" "$p")))
  done
  echo "$n"
}

cd fuzz
echo "fuzz: building the targets"
if ! cargo fuzz build >"$log_dir/build.log" 2>&1; then
  tail -n 40 "$log_dir/build.log" >&2
  die "cargo fuzz build failed"
fi

failed=0
for t in $selected; do
  mkdir -p "corpus/$t" "artifacts/$t"
  before=$(count_crashes "artifacts/$t")
  rc=0
  cargo fuzz run "$t" "corpus/$t" "seeds/$t" -- \
    "-max_total_time=$seconds" -timeout=30 -print_final_stats=1 "-artifact_prefix=$top/fuzz/artifacts/$t/" \
    >"$log_dir/$t.log" 2>&1 || rc=$?
  after=$(count_crashes "artifacts/$t")
  crashes=$((after - before))
  runs=$(sed -n 's/^stat::number_of_executed_units:[[:space:]]*//p' "$log_dir/$t.log" | tail -n 1)
  echo "fuzz: $t runs=${runs:-0} corpus=$(count_files "corpus/$t") crashes=$crashes"
  if [ "$crashes" -gt 0 ] || [ "$rc" -ne 0 ] || [ -z "$runs" ]; then
    failed=1
    if [ "$crashes" -eq 0 ]; then
      echo "fuzz: $t did not complete (exit $rc); last lines of its log:" >&2
      tail -n 30 "$log_dir/$t.log" >&2
    else
      echo "fuzz: $t crashed; the inputs are in fuzz/artifacts/$t:" >&2
      grep -E 'ERROR: |SUMMARY: |Test unit written to' "$log_dir/$t.log" | head -n 8 >&2 || true
    fi
  fi
done
exit "$failed"
