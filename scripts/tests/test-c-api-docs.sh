#!/usr/bin/env bash
# The C API reference lists exactly the functions the generated header declares (M14 step 9):
# every `lunepack_*` function of crates/lunepack-ffi/include/lunepack.h is a row of the function
# table of docs/C-API.md, no row names a function the header does not declare, no row repeats, and
# no other `lunepack_*` name in the page is a function that does not exist.
#
# The header's functions are the declarations that start a line with a return type; the table's
# rows are the lines that start with `| `lunepack_name` |`. Both extractions are checked against a
# fixture of known answer before the real files are read, and a seeded copy of the real files shows
# that a missing, an extra and a repeated row each fail.
# bash 3.2 compatible (D30).
# shellcheck disable=SC2016 # backticks in sed patterns and printf text are literal Markdown
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

HEADER=$repo/crates/lunepack-ffi/include/lunepack.h
DOC=$repo/docs/C-API.md

# header_names <header>: the function names the header declares, sorted.
header_names() {
  sed -n 's/^[A-Za-z_][^(]*[ *]\(lunepack_[a-z0-9_]*\)(.*/\1/p' "$1" | sort
}

# table_names <doc>: the function names that start a row of a table, in file order.
table_names() {
  sed -n 's/^| `\(lunepack_[a-z0-9_]*\)` |.*/\1/p' "$1"
}

# prose_names <doc>: every lunepack_ word anywhere in the page, distinct, sorted. `lunepack_ffi`
# is the library's own name (`lunepack_ffi.dll`, `lunepack_ffi*.lib`), not a function.
# shellcheck disable=SC2329 # called from compare, which runs through run_cmd
prose_names() {
  grep -o 'lunepack_[a-z0-9_]*' "$1" | grep -vx 'lunepack_ffi' | sort -u || true
}

# compare <header> <doc>: prints one line per difference and returns 1 if there is any.
# shellcheck disable=SC2329 # called through run_cmd
compare() {
  local header=$1 doc=$2 bad=0 name
  header_names "$header" >"$T_TMP/h.txt"
  table_names "$doc" >"$T_TMP/t.txt"
  sort "$T_TMP/t.txt" >"$T_TMP/ts.txt"
  prose_names "$doc" >"$T_TMP/p.txt"
  for name in $(comm -23 "$T_TMP/h.txt" "$T_TMP/ts.txt"); do
    echo "$name is declared in the header and has no row in the function table"
    bad=1
  done
  for name in $(comm -13 "$T_TMP/h.txt" "$T_TMP/ts.txt"); do
    echo "$name has a row in the function table and is not declared in the header"
    bad=1
  done
  for name in $(uniq -d "$T_TMP/ts.txt"); do
    echo "$name has more than one row in the function table"
    bad=1
  done
  for name in $(comm -13 "$T_TMP/h.txt" "$T_TMP/p.txt"); do
    echo "$name is named in the page and is not declared in the header"
    bad=1
  done
  return "$bad"
}

# --- known answer: the extractions on a fixture ------------------------------------------------------
fx=$T_TMP/fx
mkdir -p "$fx"
cat >"$fx/lunepack.h" <<'EOF'
/* lunepack_not_a_function in a comment */
#define LUNEPACK_X 1
typedef void (*LunepackProgressFn)(void *user_data);
// lunepack_in_a_line_comment(void);
uint32_t lunepack_one(void);
const char *lunepack_two(LunepackPhase phase);
LunepackStatus lunepack_three(const char *a,
                              size_t b);
void lunepack_four(const LunepackCancelToken *token);
EOF
cat >"$fx/C-API.md" <<'EOF'
Prose: `lunepack_one()`, the library `lunepack_ffi.dll` and `lunepack_ffi*.lib`.

| Function | What |
|---|---|
| `lunepack_one` | a |
| `lunepack_two` | b |
| `lunepack_three` | c |
| `lunepack_four` | d |
EOF
t_check "the header extraction finds the four fixture functions" \
  test "$(header_names "$fx/lunepack.h" | tr '\n' ' ')" = "lunepack_four lunepack_one lunepack_three lunepack_two "
t_check "the table extraction finds the four fixture rows" \
  test "$(table_names "$fx/C-API.md" | tr '\n' ' ')" = "lunepack_one lunepack_two lunepack_three lunepack_four "
run_cmd compare "$fx/lunepack.h" "$fx/C-API.md"
t_check "the fixture passes" rc_is 0

# --- the real files -----------------------------------------------------------------------------------
t_check "the header exists" test -f "$HEADER"
t_check "the page exists" test -f "$DOC"
count=$(header_names "$HEADER" | wc -l | tr -d ' ')
t_check "the header declares more than thirty functions ($count)" test "$count" -gt 30
t_check "the header declares lunepack_startup" grep -qx lunepack_startup < <(header_names "$HEADER")
t_check "the header declares lunepack_updater_stage" grep -qx lunepack_updater_stage < <(header_names "$HEADER")

run_cmd compare "$HEADER" "$DOC"
t_check "the page lists exactly the functions of the header" rc_is 0
t_check "and prints nothing" test ! -s "$OUT"

# --- seeded failures on a copy of the real page ---------------------------------------------------------
grep -v '^| `lunepack_startup_free` |' "$DOC" >"$T_TMP/doc.md" || true
run_cmd compare "$HEADER" "$T_TMP/doc.md"
t_check "a function missing from the table fails" rc_nonzero
t_check "and is named" out_has "lunepack_startup_free is declared in the header and has no row"

{
  cat "$DOC"
  printf '%s\n' '| `lunepack_invented` | not real |'
} >"$T_TMP/doc.md"
run_cmd compare "$HEADER" "$T_TMP/doc.md"
t_check "a row for a function the header lacks fails" rc_nonzero
t_check "and is named" out_has "lunepack_invented has a row in the function table and is not declared"

{
  cat "$DOC"
  printf '%s\n' '| `lunepack_abi_version` | again |'
} >"$T_TMP/doc.md"
run_cmd compare "$HEADER" "$T_TMP/doc.md"
t_check "a repeated row fails" rc_nonzero
t_check "and is named" out_has "lunepack_abi_version has more than one row"

{
  cat "$DOC"
  printf '%s\n' 'Call `lunepack_made_up` first.'
} >"$T_TMP/doc.md"
run_cmd compare "$HEADER" "$T_TMP/doc.md"
t_check "a made-up function named in prose fails" rc_nonzero
t_check "and is named" out_has "lunepack_made_up is named in the page"

grep -v 'lunepack_cancel_token_new' "$HEADER" >"$T_TMP/h.h" || true
run_cmd compare "$T_TMP/h.h" "$DOC"
t_check "a function removed from the header fails the page" rc_nonzero
t_check "and is named" out_has "lunepack_cancel_token_new has a row in the function table and is not declared"

t_finish
