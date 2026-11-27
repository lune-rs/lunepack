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
#             the public hosts of the tools it names;
#   drop      `publish refresh` has no `--drop` (S6: a release is taken out by `publish drop`, which
#             records the new feeds in the state file), so no document pairs the two, and
#             PUBLISHING.md runs `lunepack publish drop` in a fenced block (the revocation and the
#             `drop` job);
#   tools     every job of a fenced workflow that downloads a `tools-<os>` artifact refuses it,
#             before its first `tools/lunepack` command, unless the CLI is the artifact's only file
#             (the set check) and has the SHA-256 its tools job wrote (the hash check), so no file
#             planted beside the binary (a DLL on Windows) runs with the release key.
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
PATHS="|init|keys gen|keys show|keys set|keys rotate-root|pack|feed add|feed refresh|verify|inspect|setup|publish|publish fetch|publish push|publish refresh|publish drop|publish plan|publish init|publish keys|prebuilt list|prebuilt check|prebuilt sign|prebuilt verify|prebuilt fetch"
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
# shellcheck disable=SC2329 # called by the check_* functions
has_flag() {
  grep -Eq -- "(^|[^-A-Za-z])$2([^-A-Za-z]|\$)" "$1"
}

# blocks_of <md-file> [section-heading-prefix]: the content of the fenced blocks (of the section that
# starts at the heading, when given), the fences themselves removed.
# shellcheck disable=SC2329 # called by the check_* functions
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
# shellcheck disable=SC2329 # called by the check_* functions
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

# check_no_refresh_drop <md-file>: no line names `publish refresh` together with `--drop`.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_no_refresh_drop() {
  local bad=0 line
  while IFS= read -r line; do
    echo "names publish refresh with --drop: $line"
    bad=1
  done < <(grep -nE -- 'publish refresh.*--drop' "$1" || true)
  return "$bad"
}

# check_runs_drop <md-file>: a fenced block runs `lunepack publish drop`.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_runs_drop() {
  if blocks_of "$1" | commands_in | grep -q '^ publish drop|'; then
    return 0
  fi
  echo "no fenced block runs lunepack publish drop"
  return 1
}

# check_tools_set <md-file>: in the `jobs:` of the fenced blocks, every job that downloads a `tools-`
# artifact has the set check and the hash check before its first `tools/lunepack` command. Prints one
# line per missing check, naming the job, then `checked: <jobs>`; fails on a missing check or when no
# job downloads a `tools-` artifact.
# Fail closed on how the CLI is spelt: from the download until all three check lines are seen, any
# other line that names `tools/`, `tools\`, `matrix.exe` or `lunepack` counts as the first CLI command
# (`run:` under a named step, `./tools/lunepack`, a quoted path, a variable), except the one `GOT=`
# hashing line; a check line before the download does not count. A check line counts only whole: it
# starts with `if [` and ends with `exit 1; fi`, so nothing rides after it.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_tools_set() {
  blocks_of "$1" | awk '
    function end_job() {
      if (job == "" || !tools) return
      checked = checked " " job
      if (!list) { print "job " job ": no file-set listing (FILES=(tools/*)) before its first lunepack command"; bad = 1 }
      if (!refuse) { print "job " job ": no file-set refusal before its first lunepack command"; bad = 1 }
      if (!hash) { print "job " job ": no SHA-256 check before its first lunepack command"; bad = 1 }
      if ((!list || !refuse || !hash) && first != "") print "job " job ": first line naming the CLI: " first
    }
    /^jobs:[ \t]*$/ { end_job(); on = 1; job = ""; next }
    on && /^[^ \t#]/ { end_job(); on = 0; job = ""; next }
    on && /^  [A-Za-z0-9_-]+:[ \t]*$/ {
      end_job()
      job = $1
      sub(/:$/, "", job)
      tools = 0; list = 0; refuse = 0; hash = 0; ran = 0; dl = 0; first = ""
      next
    }
    on && job != "" {
      line = $0
      sub(/^[ \t]+/, "", line)
      if (line ~ /^- /) dl = 0
      if (line ~ /^(- )?uses:/) dl = (index(line, "actions/download-artifact") > 0)
      if (dl && (index(line, "name: tools-") || index(line, "name: \"tools-"))) tools = 1
      if (!tools || ran || (list && refuse && hash)) next
      if (line == "shopt -s nullglob dotglob; FILES=(tools/*); shopt -u nullglob dotglob") { list = 1; next }
      whole = (line ~ /^if \[ / && line ~ /exit 1; fi$/)
      if (whole && index(line, "\"${#FILES[@]}\" -ne 1") && index(line, "[ -L \"${FILES[0]}\" ]")) { refuse = 1; next }
      if (whole && index(line, "[ \"$GOT\" != \"$WANT\" ]")) { hash = 1; next }
      if (line ~ /^GOT="\$\(sha256sum ("tools\/[^"]*"|tools\/[^ "]*) \| cut -d. . -f1\)"$/) next
      if (line ~ /tools[\/\\]|matrix\.exe|lunepack/) { ran = 1; first = line }
    }
    END {
      end_job()
      if (checked == "") { print "no job downloads a tools- artifact"; bad = 1 }
      print "checked:" checked
      exit bad
    }
  '
}

# check_tools_crt <md-file>: in the `jobs:` of the fenced blocks, every job that runs on Windows and
# runs `cargo install` has `RUSTFLAGS: "-C target-feature=+crt-static"` in that same step (a `cargo
# install` outside a checkout does not read `.cargo/config.toml`, so the C runtime would be linked
# dynamically). Prints one line per install step without it, then `checked: <jobs>`; fails on a
# missing flag or when no Windows job runs `cargo install`. A step is the lines from one `- ` at six
# spaces of indent to the next; the flag must be exactly that value.
# shellcheck disable=SC2329 # called through run_cmd and t_check
check_tools_crt() {
  blocks_of "$1" | awk '
    function end_step() {
      if (job != "" && win && inst) {
        if (!crt) { print "job " job ": the cargo install step has no RUSTFLAGS \"-C target-feature=+crt-static\": " first; bad = 1 }
        if (index(checked " ", " " job " ") == 0) checked = checked " " job
      }
      inst = 0; crt = 0; first = ""
    }
    /^jobs:[ \t]*$/ { end_step(); on = 1; job = ""; win = 0; next }
    on && /^[^ \t#]/ { end_step(); on = 0; job = ""; next }
    on && /^  [A-Za-z0-9_-]+:[ \t]*$/ { end_step(); job = $1; sub(/:$/, "", job); win = 0; next }
    on && job != "" {
      if ($0 ~ /^    runs-on:/ && tolower($0) ~ /windows/) win = 1
      if ($0 ~ /^      - /) end_step()
      if ($0 ~ /cargo[ \t]+install/) { inst = 1; line = $0; sub(/^[ \t]+(- )?/, "", line); first = line }
      if ($0 ~ /RUSTFLAGS:[ \t]*"-C target-feature=\+crt-static"/) crt = 1
    }
    END {
      end_step()
      if (checked == "") { print "no Windows job runs cargo install"; bad = 1 }
      print "checked:" checked
      exit bad
    }
  '
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

old_drop=$T_TMP/old-drop.md
printf 'Run `lunepack publish refresh --sign K --drop 1.0.0`.\n' >"$old_drop"
run_cmd check_no_refresh_drop "$old_drop"
t_check "drop: publish refresh with --drop fails" rc_nonzero
t_check "and quotes the line" out_has "names publish refresh with --drop"
run_cmd check_no_refresh_drop "$good"
t_check "drop: a document without it passes" rc_is 0
run_cmd check_runs_drop "$old_drop"
t_check "drop: a document that does not run publish drop fails" rc_nonzero
printf '```sh\ntools/lunepack publish drop --version 1.0.0 --sign env:K\n```\n' >"$T_TMP/runs-drop.md"
run_cmd check_runs_drop "$T_TMP/runs-drop.md"
t_check "drop: a fenced publish drop passes" rc_is 0

# A workflow whose key job checks its tools artifact; the tools job (an upload) and the build job are
# not checked. The negatives are cut from it.
tools_good=$T_TMP/tools-good.md
cat >"$tools_good" <<'EOF'
```yaml
jobs:
  tools-linux:
    steps:
      - uses: actions/upload-artifact@v4
        with: { name: tools-linux, path: tools/bin/lunepack }
  build:
    steps:
      - run: ./build.sh
  push:
    steps:
      - uses: actions/download-artifact@v4
        with: { name: tools-linux, path: tools }
      - name: check the CLI against its tools job
        run: |
          shopt -s nullglob dotglob; FILES=(tools/*); shopt -u nullglob dotglob
          if [ "${#FILES[@]}" -ne 1 ] || [ "${FILES[0]}" != "tools/lunepack" ] || [ ! -f "${FILES[0]}" ] || [ -L "${FILES[0]}" ]; then echo "extra"; exit 1; fi
          GOT="$(sha256sum tools/lunepack | cut -d' ' -f1)"
          if [ -z "$WANT" ] || [ "$GOT" != "$WANT" ]; then echo "replaced"; exit 1; fi
          chmod +x tools/lunepack
      - run: tools/lunepack publish push --release-dir r --version 1.0.0 --sign env:K
```
EOF
run_cmd check_tools_set "$tools_good"
t_check "tools: a key job with both checks before its first run passes" rc_is 0
t_check "and only the job that downloads the tools artifact is checked" grep -qxF "checked: push" "$OUT"

grep -vF 'FILES' "$tools_good" >"$T_TMP/tools-no-set.md"
run_cmd check_tools_set "$T_TMP/tools-no-set.md"
t_check "tools: a key job without the set check fails" rc_nonzero
t_check "and names the job" out_has "job push: no file-set listing"
t_check "and the missing refusal" out_has "job push: no file-set refusal"

grep -vF 'shopt -s' "$tools_good" >"$T_TMP/tools-no-list.md"
run_cmd check_tools_set "$T_TMP/tools-no-list.md"
t_check "tools: a refusal without the listing fails" rc_nonzero

awk '/name: check the CLI/ { print "      - run: tools/lunepack prebuilt list" } { print }' "$tools_good" >"$T_TMP/tools-late.md"
run_cmd check_tools_set "$T_TMP/tools-late.md"
t_check "tools: a set check after the first lunepack command fails" rc_nonzero
t_check "and says before its first command" out_has "job push: no file-set listing (FILES=(tools/*)) before its first lunepack command"

# tools_early <case> <line>...: the good workflow with the lines put before its check step.
# shellcheck disable=SC2329 # called below
tools_early() {
  local out=$T_TMP/tools-early-$1.md
  shift
  INS=$(printf '%s\n' "$@") awk '/name: check the CLI/ { print ENVIRON["INS"] } { print }' "$tools_good" >"$out"
  printf '%s' "$out"
}
run_cmd check_tools_set "$(tools_early named '      - name: list' '        run: tools/lunepack prebuilt list')"
t_check "tools: a named step that runs tools/lunepack before the check fails" rc_nonzero
t_check "and quotes the line" out_has "job push: first line naming the CLI: run: tools/lunepack prebuilt list"
run_cmd check_tools_set "$(tools_early dot '      - run: ./tools/lunepack prebuilt list')"
t_check "tools: ./tools/lunepack before the check fails" rc_nonzero
run_cmd check_tools_set "$(tools_early quoted '      - run: "tools/${{ matrix.exe }}" prebuilt list')"
t_check "tools: a quoted matrix.exe path before the check fails" rc_nonzero
run_cmd check_tools_set "$(tools_early var '      - run: X=tools; "$X/lunepack" prebuilt list')"
t_check "tools: the CLI through a variable before the check fails" rc_nonzero
awk '/"\$GOT" != "\$WANT"/ { print $0 "; tools/lunepack prebuilt list"; next } { print }' "$tools_good" >"$T_TMP/tools-ride.md"
run_cmd check_tools_set "$T_TMP/tools-ride.md"
t_check "tools: a command riding after the hash check line fails" rc_nonzero
t_check "and the hash check does not count" out_has "job push: no SHA-256 check"
awk '/^ *GOT=/ { print $0 "; tools/lunepack prebuilt list"; next } { print }' "$tools_good" >"$T_TMP/tools-got.md"
run_cmd check_tools_set "$T_TMP/tools-got.md"
t_check "tools: a command riding after the hashing line fails" rc_nonzero

grep -vF '"$GOT" != "$WANT"' "$tools_good" >"$T_TMP/tools-no-hash.md"
run_cmd check_tools_set "$T_TMP/tools-no-hash.md"
t_check "tools: a key job without the hash check fails" rc_nonzero
t_check "and names the job" out_has "job push: no SHA-256 check"

printf '```yaml
jobs:
  build:
    steps:
      - run: ./build.sh
```
' >"$T_TMP/tools-none.md"
run_cmd check_tools_set "$T_TMP/tools-none.md"
t_check "tools: a workflow where no job downloads the tools artifact fails" rc_nonzero
t_check "and says so" out_has "no job downloads a tools- artifact"

# The Windows tools job builds the CLI with a static C runtime (M7-D10): the install step carries
# RUSTFLAGS, because a `cargo install` outside a checkout does not read `.cargo/config.toml`.
crt_good=$T_TMP/crt-good.md
cat >"$crt_good" <<'EOF'
```yaml
jobs:
  tools-linux:
    runs-on: ubuntu-latest
    steps:
      - run: cargo install lunepack-cli --locked --root tools
  tools-windows:
    runs-on: windows-latest
    steps:
      - run: cargo install lunepack-cli --locked --root tools
        env: { RUSTFLAGS: "-C target-feature=+crt-static" }
      - run: echo hash
```
EOF
run_cmd check_tools_crt "$crt_good"
t_check "crt: a Windows install step with the static C runtime flag passes" rc_is 0
t_check "and only the Windows job is checked" grep -qxF "checked: tools-windows" "$OUT"
grep -vF 'RUSTFLAGS' "$crt_good" >"$T_TMP/crt-none.md"
run_cmd check_tools_crt "$T_TMP/crt-none.md"
t_check "crt: a Windows install step without RUSTFLAGS fails" rc_nonzero
t_check "and names the job" out_has "job tools-windows: the cargo install step has no RUSTFLAGS"
sed 's/+crt-static/-crt-static/' "$crt_good" >"$T_TMP/crt-minus.md"
run_cmd check_tools_crt "$T_TMP/crt-minus.md"
t_check "crt: a flag that turns the static runtime off fails" rc_nonzero
awk '/^      - run: echo hash/ { print; print "        env: { RUSTFLAGS: \"-C target-feature=+crt-static\" }"; next } /RUSTFLAGS/ { next } { print }' "$crt_good" >"$T_TMP/crt-other-step.md"
run_cmd check_tools_crt "$T_TMP/crt-other-step.md"
t_check "crt: the flag on another step does not count" rc_nonzero
printf '```yaml\njobs:\n  tools-linux:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo install lunepack-cli\n```\n' >"$T_TMP/crt-nowin.md"
run_cmd check_tools_crt "$T_TMP/crt-nowin.md"
t_check "crt: a workflow with no Windows install job fails" rc_nonzero
t_check "and says so" out_has "no Windows job runs cargo install"

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

for doc in PUBLISHING.md CLI.md THREAT-MODEL.md; do
  run_cmd check_no_refresh_drop "$repo/docs/$doc"
  t_check "$doc: publish refresh has no --drop" rc_is 0
  [ "$RC" -eq 0 ] || cat "$OUT" >&2
done
run_cmd check_runs_drop "$repo/docs/PUBLISHING.md"
t_check "PUBLISHING.md: a fenced block runs publish drop" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
run_cmd check_tools_set "$repo/docs/PUBLISHING.md"
t_check "PUBLISHING.md: every key job checks its tools artifact's file set and hash" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
t_check "and the key jobs are pack, push, refresh and drop" grep -qxF "checked: pack push refresh drop" "$OUT"
run_cmd check_tools_crt "$repo/docs/PUBLISHING.md"
t_check "PUBLISHING.md: the Windows tools job builds the CLI with a static C runtime" rc_is 0
[ "$RC" -eq 0 ] || cat "$OUT" >&2
t_check "and the job is tools-windows" grep -qxF "checked: tools-windows" "$OUT"

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
