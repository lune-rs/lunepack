#!/usr/bin/env bash
# docs/PUBLISHING.md and the publish section of docs/CLI.md use only what the built CLI has
# (publish step 8).
#
# Checked against the CLI built from this checkout (cargo build --locked -p lunepack-cli; never
# skipped):
#
#   commands  every `lunepack ...` command in a fenced block names a real subcommand, and every
#             `--flag` of it is in that subcommand's `--help`;
#   flags     every `--flag` anywhere in the document (prose, tables, blocks) is in the `--help` of
#             some lunepack subcommand, bar a short list of other tools' flags (cargo, git);
#   toml      the fenced TOML block that holds `[publish]` is accepted by the CLI's config parser
#             (the command `publish plan` reaches its "run `publish init` first" refusal, which is
#             after the config parsed), so a key that does not exist is a failure;
#   names     no app, user or host of the maintainer's in the document: only example domains and
#             the public hosts of the tools it names.
#
# The checks are the functions below; the seeded negatives call them with fixtures first, so each
# check is shown to fail on what it claims to catch. bash 3.2 compatible (D30).
# shellcheck disable=SC2016 # the fixtures hold backticks that must not expand
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

(cd "$repo" && cargo build --quiet --locked -p lunepack-cli) || {
  t_fail "cargo build -p lunepack-cli failed"
  t_finish
}
CLI=${CARGO_TARGET_DIR:-$repo/target}/debug/lunepack
[ -x "$CLI" ] || {
  t_fail "no lunepack binary after the build"
  t_finish
}

# The flags of tools other than lunepack that the documents use.
OTHER_FLAGS=" --locked --root --format "

# Every subcommand path whose help is read.
PATHS="|init|keys gen|keys show|keys set|keys rotate-root|pack|feed add|feed refresh|verify|inspect|setup|publish|publish fetch|publish push|publish refresh|publish plan|publish init|prebuilt list|prebuilt check|prebuilt sign|prebuilt verify|prebuilt fetch"
HELP_DIR=$T_TMP/help
mkdir -p "$HELP_DIR"

# help_file <path words>: the file holding `lunepack <path> --help`, made on first use; empty status
# when the path is not a command.
help_file() {
  local words=$1 file
  file=$HELP_DIR/$(printf '%s' "$words" | tr ' ' '_')
  if [ ! -f "$file" ]; then
    # shellcheck disable=SC2086 # the words are separate arguments
    if ! "$CLI" $words --help >"$file" 2>/dev/null; then
      rm -f "$file"
      return 1
    fi
  fi
  printf '%s' "$file"
}

ALL_HELP=$T_TMP/all-help.txt
: >"$ALL_HELP"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  f=$(help_file "$p") || {
    t_fail "lunepack $p --help failed"
    t_finish
  }
  cat "$f" >>"$ALL_HELP"
done < <(printf '%s\n' "$PATHS" | tr '|' '\n')

# has_flag <help-file> <--flag>
has_flag() {
  grep -Eq -- "(^|[^-A-Za-z])$2([^-A-Za-z]|\$)" "$1"
}

# blocks_of <md-file> [section-heading-prefix]: the content of the fenced blocks (of the section that
# starts at the heading, when given), the fences themselves removed.
blocks_of() {
  awk -v h="${2:-}" '
    h != "" && index($0, h) == 1 { on = 1; next }
    h != "" && /^## / { on = 0 }
    /^[ \t]*(```|~~~)/ { if (h == "" || on) fence = !fence; next }
    fence { print }
  ' "$1"
}

# commands_in <text-on-stdin>: one line per lunepack command, "<up to three words>|<flags>".
# A trailing backslash, or a line that starts with a flag or a "[" after a command, continues it.
commands_in() {
  awk '
    function flush(   n, i, t, words, flags, k, stop) {
      if (acc == "") return
      n = split(acc, tok, /[ \t]+/)
      for (i = 1; i <= n; i++) {
        t = tok[i]
        sub(/^.*\//, "", t)
        if (t != "lunepack") continue
        words = ""; flags = ""; k = 0; stop = 0
        for (j = i + 1; j <= n && !stop; j++) {
          u = tok[j]
          if (u ~ /^(&&|\|\||;|\|)$/) { stop = 1; break }
          if (u ~ /^--?[a-zA-Z]/ || u ~ /^\[--/) {
            if (match(u, /--[a-z][a-z-]*/)) flags = flags " " substr(u, RSTART, RLENGTH)
            k = 99
            continue
          }
          if (k < 3 && u ~ /^[a-z][a-z-]*$/) { words = words " " u; k++ } else { k = 99 }
        }
        if (words != "" || flags != "") print words "|" flags
      }
      acc = ""
    }
    {
      line = $0
      sub(/^[ \t]+/, "", line)
      cont = (line ~ /\\[ \t]*$/)
      sub(/[ \t]*\\[ \t]*$/, "", line)
      if (acc != "" && (joined || line ~ /^(--|\[)/)) {
        acc = acc " " line
      } else {
        flush()
        acc = line
      }
      joined = cont
    }
    END { flush() }
  '
}

# check_commands <md-file> [section-heading-prefix]: prints every problem, returns 1 if any.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_commands() {
  local line words flags a b c path file flag bad=0
  while IFS= read -r line; do
    words=${line%%|*}
    flags=${line#*|}
    # shellcheck disable=SC2086 # split on purpose
    set -- $words
    a=${1:-}
    b=${2:-}
    c=${3:-}
    path=
    file=
    for cand in "$a $b $c" "$a $b" "$a"; do
      cand=${cand%" "}
      cand=${cand%" "}
      [ -n "$cand" ] || continue
      if file=$(help_file "$cand"); then
        path=$cand
        break
      fi
    done
    if [ -z "$path" ]; then
      echo "not a lunepack command: lunepack$words"
      bad=1
      continue
    fi
    for flag in $flags; do
      [ "$flag" = --help ] && continue
      has_flag "$file" "$flag" || {
        echo "lunepack $path has no $flag"
        bad=1
      }
    done
  done < <(blocks_of "$1" "${2:-}" | commands_in)
  return "$bad"
}

# check_flags <md-file> [section-heading-prefix]: every --flag of the text is some subcommand's.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_flags() {
  local flag bad=0 text
  if [ -n "${2:-}" ]; then
    text=$(awk -v h="$2" 'index($0, h) == 1 { on = 1; next } /^## / { on = 0 } on' "$1")
  else
    text=$(cat "$1")
  fi
  for flag in $(printf '%s\n' "$text" | grep -Eo -- '--[a-z][a-z-]*' | sort -u); do
    case "$OTHER_FLAGS" in *" $flag "*) continue ;; esac
    has_flag "$ALL_HELP" "$flag" || {
      echo "$flag is in no lunepack --help"
      bad=1
    }
  done
  return "$bad"
}

ROOT_KEY=0000000000000000000000000000000000000000000000000000000000000001

# check_toml <md-file> [section-heading-prefix]: every fenced TOML block with a [publish] table and
# no app_id parses, in a config with the root of lunepack init and the blocks [update] and [install]
# when the block has none.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_toml() {
  local dir n=0 bad=0 block cfg
  dir=$(mktemp -d "$T_TMP/toml.XXXXXX")
  # Split the fenced content into blocks: awk over the raw file, one file per block.
  awk -v dir="$dir" -v h="${2:-}" '
    h != "" && index($0, h) == 1 { on = 1; next }
    h != "" && /^## / { on = 0 }
    /^[ \t]*(```|~~~)/ {
      if (h == "" || on) {
        if (fence) { close(out); fence = 0 } else { n++; out = dir "/block-" n; fence = 1; printf "" > out }
      }
      next
    }
    fence { print >> out }
  ' "$1"
  for block in "$dir"/block-*; do
    [ -f "$block" ] || continue
    grep -q '^\[publish\]' "$block" || continue
    grep -q '^app_id' "$block" && continue
    n=$((n + 1))
    cfg=$dir/cfg-$n.toml
    {
      printf 'app_id = "org.example.hello"\n\n[root]\nthreshold = 1\nkeys = ["%s"]\n\n' "$ROOT_KEY"
      if ! grep -q '^\[update\]' "$block"; then
        printf '[update]\nfeed = "https://updates.example.com/hello/"\n\n[install]\nentry = "bin/hello"\nname = "Hello"\n\n'
      fi
      cat "$block"
    } >"$cfg"
    # A parsed config reaches the store, which is an absent directory: "run `lunepack publish init`
    # first". A config that does not parse fails before, naming the key.
    if "$CLI" --config "$cfg" publish plan --store-dir "$dir/no-store" >"$dir/out-$n" 2>&1; then
      echo "block $n: publish plan succeeded on an empty store"
      bad=1
    elif ! grep -Fq 'publish init' "$dir/out-$n"; then
      echo "block $n: the config is not accepted: $(head -n 1 "$dir/out-$n")"
      bad=1
    fi
  done
  if [ "$n" -eq 0 ]; then
    echo "no TOML block with a [publish] table"
    bad=1
  fi
  return "$bad"
}

# check_names <md-file>: no maintainer's app, user or host.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_names() {
  local bad=0 url host
  # The maintainer's app and user names are spelled in pieces, so this file does not hold them.
  if grep -Eiq "lune""term|whip""spot|iz""zat" "$1"; then
    echo "the document names an app or user of the maintainer's"
    bad=1
  fi
  while IFS= read -r url; do
    host=${url#*://}
    host=${host%%:*}
    case $host in
      example.com | *.example.com | example.org | *.example.org | example.net | *.example.net | github.com | docs.github.com | crates.io) ;;
      *)
        echo "the document names the host $host"
        bad=1
        ;;
    esac
  done < <(grep -Eo 'https?://[^/" )>`]+' "$1" | sort -u)
  return "$bad"
}

# --- seeded negatives and positives --------------------------------------------------------------
good=$T_TMP/good.md
cat >"$good" <<'EOF'
# Good

```sh
lunepack publish push --release-dir a \
    --release-dir b --version 1.0.0 --sign env:K --dry-run
tools/bin/lunepack publish refresh --sign env:K && echo done
lunepack setup release --version 1.0.0 --target linux-x86_64
```

```toml
[publish]
prefix = "hello"
store = "r2"
account_id_env = "EXAMPLE_ID"
access_key_env = "EXAMPLE_KEY"
secret_key_env = "EXAMPLE_SECRET"
public_bucket = "example-updates"
private_bucket = "example-updates-private"
```

Prose with `--dry-run`, `--locked` and https://updates.example.com/x and https://github.com/a.
EOF
run_cmd check_commands "$good"
t_check "commands: a document of real commands passes" rc_is 0
run_cmd check_flags "$good"
t_check "flags: a document of real flags passes" rc_is 0
run_cmd check_toml "$good"
t_check "toml: a [publish] table that parses passes" rc_is 0
run_cmd check_names "$good"
t_check "names: example hosts pass" rc_is 0

bad_flag=$T_TMP/bad-flag.md
printf '```sh\nlunepack publish push --release-dir a --bogus-flag x\n```\n' >"$bad_flag"
run_cmd check_commands "$bad_flag"
t_check "commands: a flag the subcommand lacks fails" rc_nonzero
t_check "and names the subcommand and the flag" out_has "lunepack publish push has no --bogus-flag"

bad_cmd=$T_TMP/bad-cmd.md
printf '```sh\nlunepack publish explode --dry-run\n```\n' >"$bad_cmd"
run_cmd check_commands "$bad_cmd"
t_check "commands: a command that does not exist fails" rc_nonzero

bad_cont=$T_TMP/bad-cont.md
printf '```sh\nlunepack publish push --release-dir a \\\n    --version 1 --nope y\n```\n' >"$bad_cont"
run_cmd check_commands "$bad_cont"
t_check "commands: a flag on a continued line is read" rc_nonzero

bad_prose=$T_TMP/bad-prose.md
printf 'Use `--made-up-flag` here.\n' >"$bad_prose"
run_cmd check_flags "$bad_prose"
t_check "flags: a flag in prose that no subcommand has fails" rc_nonzero
t_check "and names it" out_has "--made-up-flag is in no lunepack --help"

bad_toml=$T_TMP/bad-toml.md
cat >"$bad_toml" <<'EOF'
```toml
[publish]
prefix = "hello"
store = "r2"
account_id_env = "EXAMPLE_ID"
access_key_env = "EXAMPLE_KEY"
secret_key_env = "EXAMPLE_SECRET"
public_bucket = "example-updates"
private_bucket = "example-updates-private"
retention = 5
```
EOF
run_cmd check_toml "$bad_toml"
t_check "toml: a key that does not exist fails" rc_nonzero
t_check "and says the config is not accepted" out_has "the config is not accepted"
printf 'No toml here.\n' >"$T_TMP/no-toml.md"
run_cmd check_toml "$T_TMP/no-toml.md"
t_check "toml: a document without the block fails" rc_nonzero

bad_name=$T_TMP/bad-name.md
printf 'See https://updates.mycompany.test/app and %s.\n' "Whip""spot" >"$bad_name"
run_cmd check_names "$bad_name"
t_check "names: a maintainer's app name and a real host fail" rc_nonzero
t_check "and names the host" out_has "the document names the host updates.mycompany.test"

# --- the real documents ---------------------------------------------------------------------------
run_cmd check_commands "$repo/docs/PUBLISHING.md"
t_check "PUBLISHING.md: every command and flag exists" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
run_cmd check_flags "$repo/docs/PUBLISHING.md"
t_check "PUBLISHING.md: every --flag is a lunepack flag" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
run_cmd check_toml "$repo/docs/PUBLISHING.md"
t_check "PUBLISHING.md: the [publish] example is accepted by the CLI" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
run_cmd check_names "$repo/docs/PUBLISHING.md"
t_check "PUBLISHING.md: no maintainer app, user or host" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2

section="## Publishing: \`lunepack publish\`"
run_cmd check_commands "$repo/docs/CLI.md" "$section"
t_check "CLI.md: every command of the publish section exists with its flags" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
run_cmd check_flags "$repo/docs/CLI.md" "$section"
t_check "CLI.md: every --flag of the publish section is a lunepack flag" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
run_cmd check_toml "$repo/docs/CLI.md" "$section"
t_check "CLI.md: the [publish] example is accepted by the CLI" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
run_cmd check_names "$repo/docs/CLI.md"
t_check "CLI.md: no maintainer app, user or host" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2

t_finish
