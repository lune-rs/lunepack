#!/usr/bin/env bash
# SECURITY.md lists the project's key sets exactly as the built CLI reports them (M13-D30, step 16).
#
# `lunepack prebuilt list --json` reports the key sets compiled into the CLI under `roots`; the
# section "## The project's key sets" of SECURITY.md must hold, for every key of every set, the row
#
#   | <version> | <threshold> | `<public key>` | `<key id>` | current |      (retired for an earlier set)
#
# and no 64-hex string that is not one of the CLI's public keys or key ids. With no key set the
# section must say "No project key has been published yet." and hold no 64-hex string at all.
# The check is the function check_key_docs <security-text-file> <list-json-file>, which the seeded
# negatives call with fixtures; the last case runs it on this repository's SECURITY.md and the CLI
# built from this checkout (cargo build --locked -p lunepack-cli; never skipped).
# bash 3.2 compatible (D30).
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
command -v jq >/dev/null 2>&1 || {
  t_fail "jq is not on PATH"
  t_finish
}

HEADING="## The project's key sets"
NO_KEY_SENTENCE="No project key has been published yet."

# check_key_docs <security-text-file> <list-json-file>: prints every problem, returns 1 if any.
# shellcheck disable=SC2329 # called through run_cmd or t_check
check_key_docs() {
  local doc=$1 json=$2 section roots i j keys pub id version threshold state row hex bad=0
  section=$(awk -v h="$HEADING" '$0 == h { on = 1; next } /^## / { on = 0 } on' "$doc")
  if [ -z "$section" ]; then
    echo "SECURITY.md has no section \"$HEADING\""
    return 1
  fi
  roots=$(jq -er '.roots | if type == "array" then length else error("roots") end' "$json") || {
    echo "the CLI's list --json has no roots array"
    return 1
  }
  keys=
  if [ "$roots" -eq 0 ]; then
    grep -Fq -- "$NO_KEY_SENTENCE" <<<"$section" || {
      echo "the CLI has no key set, and the section lacks: $NO_KEY_SENTENCE"
      bad=1
    }
  else
    i=0
    while [ "$i" -lt "$roots" ]; do
      version=$(jq -er ".roots[$i].version" "$json")
      threshold=$(jq -er ".roots[$i].threshold" "$json")
      if [ "$(jq -er ".roots[$i].current" "$json")" = true ]; then state=current; else state=retired; fi
      j=0
      while [ "$j" -lt "$(jq -er ".roots[$i].keys | length" "$json")" ]; do
        pub=$(jq -er ".roots[$i].keys[$j].public" "$json")
        id=$(jq -er ".roots[$i].keys[$j].id" "$json")
        keys="$keys $pub $id"
        row="| $version | $threshold | \`$pub\` | \`$id\` | $state |"
        grep -Fxq -- "$row" <<<"$section" || {
          echo "the section lacks the row of key set $version, key $((j + 1)): $row"
          bad=1
        }
        j=$((j + 1))
      done
      i=$((i + 1))
    done
  fi
  # Every 64-hex string of the section must be a public key or an id the CLI reported.
  # shellcheck disable=SC2013 # each match is one 64-hex word, never a line with spaces
  for hex in $(grep -Eo '[0-9a-f]{64}' <<<"$section" | sort -u); do
    case " $keys " in
      *" $hex "*) ;;
      *)
        echo "the section holds a 64-hex string the CLI does not report (${hex:0:8}...${hex:60})"
        bad=1
        ;;
    esac
  done
  return "$bad"
}

# --- fixtures ---------------------------------------------------------------------------------------
hx() { printf '%064x' "$1"; }
P1=$(hx 101)
I1=$(hx 102)
P2=$(hx 201)
I2=$(hx 202)
P3=$(hx 203)
I3=$(hx 204)

one_set_json=$T_TMP/one.json
two_sets_json=$T_TMP/two.json
none_json=$T_TMP/none.json
printf '{"roots":[{"version":1,"threshold":1,"current":true,"keys":[{"public":"%s","id":"%s"}]}]}\n' "$P1" "$I1" >"$one_set_json"
printf '{"roots":[{"version":1,"threshold":1,"current":false,"keys":[{"public":"%s","id":"%s"}]},{"version":2,"threshold":2,"current":true,"keys":[{"public":"%s","id":"%s"},{"public":"%s","id":"%s"}]}]}\n' \
  "$P1" "$I1" "$P2" "$I2" "$P3" "$I3" >"$two_sets_json"
printf '{"roots":[]}\n' >"$none_json"

table_head='| Version | Threshold | Public key | Key id | State |
| --- | --- | --- | --- | --- |'
write_doc() { # file, then the body of the section on stdin
  {
    printf '# Security\n\nIntro with a stray %s that is outside the section.\n\n%s\n\n' "$(hx 999)" "$HEADING"
    cat
    printf '\n## Another section\n\nMore text.\n'
  } >"$1"
}

# No key set.
write_doc "$T_TMP/none-ok.md" <<EOF
$NO_KEY_SENTENCE
EOF
run_cmd check_key_docs "$T_TMP/none-ok.md" "$none_json"
t_check "no key set and the sentence: passes" rc_is 0

write_doc "$T_TMP/none-no-sentence.md" <<EOF
Keys will come later.
EOF
run_cmd check_key_docs "$T_TMP/none-no-sentence.md" "$none_json"
t_check "no key set and no sentence: fails" rc_nonzero
t_check "and says which sentence" out_has "$NO_KEY_SENTENCE"

write_doc "$T_TMP/none-with-hex.md" <<EOF
$NO_KEY_SENTENCE

$table_head
| 1 | 1 | \`$P1\` | \`$I1\` | current |
EOF
run_cmd check_key_docs "$T_TMP/none-with-hex.md" "$none_json"
t_check "no key set but a 64-hex string in the section: fails" rc_nonzero
t_check "and says the CLI does not report it" out_has "the CLI does not report"

# One key set.
write_doc "$T_TMP/one-ok.md" <<EOF
$table_head
| 1 | 1 | \`$P1\` | \`$I1\` | current |
EOF
run_cmd check_key_docs "$T_TMP/one-ok.md" "$one_set_json"
t_check "one key set, its row: passes" rc_is 0

write_doc "$T_TMP/one-sentence.md" <<EOF
$NO_KEY_SENTENCE
EOF
run_cmd check_key_docs "$T_TMP/one-sentence.md" "$one_set_json"
t_check "a key set exists but the text says none: fails" rc_nonzero
t_check "and names the missing row" out_has "the section lacks the row of key set 1, key 1"

# A key id missing from the text.
write_doc "$T_TMP/one-no-id.md" <<EOF
$table_head
| 1 | 1 | \`$P1\` | \`$(hx 7)\` | current |
EOF
run_cmd check_key_docs "$T_TMP/one-no-id.md" "$one_set_json"
t_check "a key id that is not the CLI's (the right one missing): fails" rc_nonzero
t_check "and names the row" out_has "the section lacks the row of key set 1, key 1"
t_check "and the foreign string" out_has "the CLI does not report"

# A key in the text that the CLI does not have.
write_doc "$T_TMP/one-extra.md" <<EOF
$table_head
| 1 | 1 | \`$P1\` | \`$I1\` | current |
| 2 | 1 | \`$P2\` | \`$I2\` | current |
EOF
run_cmd check_key_docs "$T_TMP/one-extra.md" "$one_set_json"
t_check "a key in the text that the CLI does not have: fails" rc_nonzero
t_check "and says so" out_has "the CLI does not report"

# The state column must follow the CLI.
write_doc "$T_TMP/one-state.md" <<EOF
$table_head
| 1 | 1 | \`$P1\` | \`$I1\` | retired |
EOF
run_cmd check_key_docs "$T_TMP/one-state.md" "$one_set_json"
t_check "the wrong state (retired for the current set): fails" rc_nonzero

# Two sets, three keys.
write_doc "$T_TMP/two-ok.md" <<EOF
$table_head
| 1 | 1 | \`$P1\` | \`$I1\` | retired |
| 2 | 2 | \`$P2\` | \`$I2\` | current |
| 2 | 2 | \`$P3\` | \`$I3\` | current |
EOF
run_cmd check_key_docs "$T_TMP/two-ok.md" "$two_sets_json"
t_check "two key sets, three rows, one retired: passes" rc_is 0

write_doc "$T_TMP/two-short.md" <<EOF
$table_head
| 1 | 1 | \`$P1\` | \`$I1\` | retired |
| 2 | 2 | \`$P2\` | \`$I2\` | current |
EOF
run_cmd check_key_docs "$T_TMP/two-short.md" "$two_sets_json"
t_check "a key of the current set missing from the text: fails" rc_nonzero
t_check "and names the key set and key" out_has "the section lacks the row of key set 2, key 2"

# A file without the section.
printf '# Security\n\nNothing here.\n' >"$T_TMP/no-section.md"
run_cmd check_key_docs "$T_TMP/no-section.md" "$none_json"
t_check "no section at all: fails" rc_nonzero

# --- the real SECURITY.md and the CLI built from this checkout --------------------------------------
(cd "$repo" && cargo build --quiet --locked -p lunepack-cli) || {
  t_fail "cargo build -p lunepack-cli failed"
  t_finish
}
REAL_CLI=${CARGO_TARGET_DIR:-$repo/target}/debug/lunepack
[ -x "$REAL_CLI" ] || {
  t_fail "no lunepack binary after the build"
  t_finish
}
real_json=$T_TMP/real.json
# `prebuilt list --json` exits 1 in the state inconsistent after printing the report; the report is
# what is read, and the state is the CLI's own test to fail.
"$REAL_CLI" prebuilt list --json >"$real_json" 2>/dev/null || true
# shellcheck disable=SC2329 # called through run_cmd or t_check
has_roots() { jq -e '.roots | type == "array"' "$1" >/dev/null; }
t_check "the CLI printed a list report with roots" has_roots "$real_json"
run_cmd check_key_docs "$repo/SECURITY.md" "$real_json"
if [ "$RC" -ne 0 ]; then
  cat "$OUT" >&2
fi
t_check "SECURITY.md lists the key sets of the built CLI" rc_is 0

t_finish
