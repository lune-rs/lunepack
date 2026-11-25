#!/usr/bin/env bash
# Tests for scripts/fuzz.sh without Docker (M13 step 3): the argument handling, the refusals off
# Linux, and the target list: --list must equal the harness tables of the core and of the codec
# crate, and a difference between the tables, fuzz/Cargo.toml and fuzz/fuzz_targets/ must fail.
# Nothing here starts a container or a fuzzer.
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
repo=$(cd "$here/../.." && pwd)
SCRIPT=$repo/scripts/fuzz.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

run_cmd bash "$SCRIPT" --bogus
t_check "an unknown option is a usage error" rc_is 2
t_check "usage is printed" out_has "usage:"

run_cmd bash "$SCRIPT" --help
t_check "--help exits 0" rc_is 0
t_check "--help prints usage" out_has "usage:"

run_cmd bash "$SCRIPT" --seconds
t_check "--seconds without a value is a usage error" rc_is 2
for bad in 0 abc 5x -3 "" 007 1234567; do
  run_cmd bash "$SCRIPT" --list --seconds "$bad"
  t_check "--seconds '$bad' is a usage error" rc_is 2
done
run_cmd bash "$SCRIPT" --docker --inside --list
t_check "--docker with --inside is a usage error" rc_is 2
run_cmd bash "$SCRIPT" --list nosuchtarget
t_check "--list with an unknown target still lists (the list is the answer)" rc_is 0
run_cmd bash "$SCRIPT" nosuchtarget
t_check "an unknown target is a usage error" rc_is 2
t_check "the unknown target is named" out_has "no such target: nosuchtarget"

# --- the list ----------------------------------------------------------------------------------
# The expected set, derived here a second way: every `("name", fn)` entry of the two tables.
expected() {
  {
    sed -n '/pub const HARNESSES/,/^];/p' "$repo/crates/lunepack-core/src/fuzz.rs"
    sed -n '/pub const HARNESSES/,/];/p' "$repo/crates/lunepack-codec-lzma/src/fuzz.rs"
  } | grep -o '("[a-z0-9_]*", *[a-z0-9_]*)' | sed 's/^("//; s/".*//' | LC_ALL=C sort
}
run_cmd bash "$SCRIPT" --list
t_check "--list succeeds" rc_is 0
listed=$(LC_ALL=C sort "$OUT")
t_check "--list equals the harness tables of the core and the codec crate" test "$listed" = "$(expected)"
t_check "--list names the codec crate's harnesses" grep -qx patch "$OUT"
t_check "--list names a core harness" grep -qx deltas "$OUT"
t_check "--list has one line per target and no duplicates" test "$(wc -l <"$OUT" | tr -d ' ')" = "$(sort -u "$OUT" | wc -l | tr -d ' ')"
t_check "--list has 20 targets" test "$(wc -l <"$OUT" | tr -d ' ')" = 20

# --- a difference between the three sources fails -----------------------------------------------
tree=$T_TMP/tree
fresh_tree() {
  rm -rf "$tree"
  mkdir -p "$tree/scripts" "$tree/fuzz" "$tree/crates/lunepack-core/src" "$tree/crates/lunepack-codec-lzma/src"
  cp "$SCRIPT" "$tree/scripts/fuzz.sh"
  cp "$repo/fuzz/Cargo.toml" "$tree/fuzz/Cargo.toml"
  cp -R "$repo/fuzz/fuzz_targets" "$tree/fuzz/fuzz_targets"
  cp "$repo/crates/lunepack-core/src/fuzz.rs" "$tree/crates/lunepack-core/src/fuzz.rs"
  cp "$repo/crates/lunepack-codec-lzma/src/fuzz.rs" "$tree/crates/lunepack-codec-lzma/src/fuzz.rs"
}
fresh_tree
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "the copied tree lists (control)" rc_is 0

# A harness without a [[bin]] and without a target file.
fresh_tree
sed 's|^    ("ui", ui),|    ("ui", ui),\n    ("extra", ui),|' "$tree/crates/lunepack-core/src/fuzz.rs" >"$tree/f.rs"
mv "$tree/f.rs" "$tree/crates/lunepack-core/src/fuzz.rs"
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "a harness without a target fails" rc_is 1
t_check "it names the harness" out_has "harness without a [[bin]]: extra"
t_check "it names the missing target file" out_has "harness without a target file: extra"

# A harness of the codec crate without a target.
fresh_tree
sed 's|("patch", patch)\]|("patch", patch), ("more", patch)]|' "$tree/crates/lunepack-codec-lzma/src/fuzz.rs" >"$tree/f.rs"
mv "$tree/f.rs" "$tree/crates/lunepack-codec-lzma/src/fuzz.rs"
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "a codec-crate harness without a target fails" rc_is 1
t_check "it names the codec-crate harness" out_has "harness without a [[bin]]: more"

# A [[bin]] without a harness.
fresh_tree
printf '\n[[bin]]\nname = "orphan"\npath = "fuzz_targets/orphan.rs"\n' >>"$tree/fuzz/Cargo.toml"
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "a [[bin]] without a harness fails" rc_is 1
t_check "it names the [[bin]]" out_has "[[bin]] without a harness: orphan"

# A [[bin]] removed (a target left out of the Cargo manifest).
fresh_tree
awk '
  /^\[\[bin\]\]/ { held = $0; next }
  held != "" { if ($0 == "name = \"ui\"") { skip = 1 } else { print held } held = "" }
  skip && /^$/ { skip = 0; next }
  skip { next }
  { print }
' "$tree/fuzz/Cargo.toml" >"$tree/c.toml"
mv "$tree/c.toml" "$tree/fuzz/Cargo.toml"
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "a harness left out of fuzz/Cargo.toml fails" rc_is 1
t_check "it names the harness left out" out_has "harness without a [[bin]]: ui"

# A target file removed, and a stray target file.
fresh_tree
rm "$tree/fuzz/fuzz_targets/ui.rs"
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "a removed target file fails" rc_is 1
t_check "it names the removed target file" out_has "harness without a target file: ui"
fresh_tree
cp "$tree/fuzz/fuzz_targets/ui.rs" "$tree/fuzz/fuzz_targets/stray.rs"
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "a stray target file fails" rc_is 1
t_check "it names the stray target file" out_has "target file without a harness: stray"

# A table that cannot be found fails closed.
fresh_tree
sed 's|pub const HARNESSES|pub const OTHERS|' "$tree/crates/lunepack-codec-lzma/src/fuzz.rs" >"$tree/f.rs"
mv "$tree/f.rs" "$tree/crates/lunepack-codec-lzma/src/fuzz.rs"
run_cmd bash "$tree/scripts/fuzz.sh" --list
t_check "a missing harness table fails" rc_is 1
t_check "it says which table" out_has "no harness table found in crates/lunepack-codec-lzma/src/fuzz.rs"

# --- refusals ------------------------------------------------------------------------------------
if [ "$(uname -s)" != Linux ]; then
  run_cmd bash "$SCRIPT" --inside
  t_check "--inside off Linux is refused" rc_is 1
  t_check "the refusal says Linux only" out_has "Linux only"
fi

# The Dockerfile pins what the contract says: the base by digest, a dated nightly, an exact cargo-fuzz.
dockerfile=$repo/scripts/fuzz.Dockerfile
t_check "the image pins its base by digest" grep -Eq '^FROM [^ ]+@sha256:[0-9a-f]{64}$' "$dockerfile"
t_check "the image pins a dated nightly" grep -Eq 'toolchain install nightly-20[0-9]{2}-[0-9]{2}-[0-9]{2} ' "$dockerfile"
t_check "the image pins cargo-fuzz to an exact version" grep -Eq 'cargo install --locked --version [0-9]+\.[0-9]+\.[0-9]+ cargo-fuzz' "$dockerfile"
nightly=$(sed -n 's/.*toolchain install \(nightly-[0-9-]*\) .*/\1/p' "$dockerfile")
t_check "the script runs the image's nightly" grep -q "RUSTUP_TOOLCHAIN=$nightly" "$SCRIPT"

t_finish
