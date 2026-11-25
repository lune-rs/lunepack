#!/usr/bin/env bash
# Every relative link in a tracked Markdown file resolves to a tracked file or directory
# (M13-D22, step 16). The private files (CLAUDE.md, docs/DECISIONS.md, docs/STATE.md) are links
# into a private store and are not tracked, so a link to one is dangling in a clean clone even
# though it resolves on the maintainer's disk: the check reads `git ls-files`, never the disk.
#
# What counts as a link: `[text](target)` and a reference definition `[name]: target`, outside
# fenced code blocks and inline code. Skipped: a target with a scheme (`https:`, `mailto:`), a
# target that is only a fragment, and the fragment or query of any other target (anchors are not
# checked). A target that starts with `/` is read from the repository root; any other is read from
# the directory of the file that holds it. A target that leaves the repository fails.
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

# links_of <file>: the link targets of a Markdown file, one per line.
# shellcheck disable=SC2329 # called by check_links
links_of() {
  awk '
    /^[ \t]*(```|~~~)/ { fence = !fence; next }
    fence { next }
    {
      line = $0
      gsub(/`[^`]*`/, "", line)
      if (match(line, /^[ ]?[ ]?[ ]?\[[^]]+\]:[ \t]*[^ \t]+/)) {
        s = substr(line, RSTART, RLENGTH)
        sub(/^[ ]*\[[^]]+\]:[ \t]*/, "", s)
        print s
        next
      }
      while (match(line, /\]\([^)]*\)/)) {
        print substr(line, RSTART + 2, RLENGTH - 3)
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' "$1"
}

# normalise <dir> <relative>: the path of <relative> under <dir> with . and .. folded, or nothing
# when it leaves the root. <dir> is "" for the root itself.
# shellcheck disable=SC2329 # called by check_links
normalise() {
  local dir=$1 rel=$2 part joined
  local -a out
  out=()
  local IFS=/
  # shellcheck disable=SC2086
  set -- $dir $rel
  for part in "$@"; do
    case $part in
      '' | .) ;;
      ..)
        [ "${#out[@]}" -gt 0 ] || return 1
        out=("${out[@]:0:${#out[@]}-1}")
        ;;
      *) out+=("$part") ;;
    esac
  done
  joined=
  for part in ${out[@]+"${out[@]}"}; do
    joined=${joined:+$joined/}$part
  done
  printf '%s' "$joined"
}

# check_links <root> <tracked-list-file>: prints one line per dangling link and returns 1 if there
# is any. <tracked-list-file> holds `git ls-files` of <root>, one path per line.
# shellcheck disable=SC2329 # called through run_cmd
check_links() {
  local root=$1 list=$2 md target path dir resolved bad=0
  # shellcheck disable=SC2094 # $list is only read, by this loop and the grep inside it; nothing writes it
  while IFS= read -r md; do
    case $md in
      *.md) ;;
      *) continue ;;
    esac
    [ -f "$root/$md" ] && [ ! -L "$root/$md" ] || continue
    dir=${md%/*}
    [ "$dir" != "$md" ] || dir=
    while IFS= read -r target; do
      target=${target#<}
      target=${target%>}
      case $target in
        '' | '#'*) continue ;;
      esac
      scheme=${target%%:*}
      if [ "$scheme" != "$target" ]; then
        case $scheme in
          *[!A-Za-z0-9+.-]*) ;;
          *) continue ;;
        esac
      fi
      path=${target%%[#?]*}
      [ -n "$path" ] || continue
      case $path in
        /*) resolved=$(normalise "" "${path#/}") || resolved=@outside ;;
        *) resolved=$(normalise "$dir" "$path") || resolved=@outside ;;
      esac
      if [ "$resolved" = @outside ] || [ -z "$resolved" ]; then
        echo "$md: $target leaves the repository"
        bad=1
        continue
      fi
      if grep -Fxq -- "$resolved" "$list" || grep -Fq -- "$resolved/" "$list"; then
        continue
      fi
      echo "$md: $target is not a tracked file ($resolved)"
      bad=1
    done < <(links_of "$root/$md")
  done <"$list"
  return "$bad"
}

# --- seeded fixture: a repository that models today's dangling links -------------------------------
fx=$T_TMP/fx
mkdir -p "$fx/docs/sub" "$fx/private-store"
g -C "$fx" init --quiet
(
  cd "$fx"
  printf '# a\n' >docs/b.md
  printf '# c\n' >docs/sub/c.md
  printf 'data\n' >docs/data.txt
  # A link into a private store: it exists on this disk, but the file is not tracked.
  printf '# private\n' >private-store/DECISIONS.md
  ln -s ../private-store/DECISIONS.md docs/DECISIONS.md
  cat >README.md <<'EOF'
# fixture

Fine: [b](docs/b.md), [c](./docs/sub/c.md#heading), [dir](docs/sub/), [data](docs/data.txt?raw=1),
[web](https://example.org/x.md), [mail](mailto:a@example.org), [here](#top), [abs](/docs/b.md).

```
[in a fence](docs/missing-in-fence.md)
```

Inline code is not a link: `[x](docs/missing-in-code.md)`.

[ref]: docs/b.md
EOF
  cat >docs/sub/c.md <<'EOF'
# c

Up: [a](../b.md) and [readme](../../README.md).
EOF
  g add README.md docs/b.md docs/sub/c.md docs/data.txt
)
list=$T_TMP/list.txt
g -C "$fx" ls-files >"$list"

run_cmd check_links "$fx" "$list"
t_check "a fixture of good links passes" rc_is 0
t_check "and prints nothing" test ! -s "$OUT"

# The dangling cases, one file each, so every message is attributed.
add_case() { # name content
  printf '%s\n' "$2" >"$fx/docs/$1.md"
  g -C "$fx" add "docs/$1.md"
  g -C "$fx" ls-files >"$list"
}

add_case missing '[gone](nowhere.md)'
run_cmd check_links "$fx" "$list"
t_check "a link to a file that does not exist fails" rc_nonzero
t_check "and names the file and the link" out_has "docs/missing.md: nowhere.md is not a tracked file (docs/nowhere.md)"
rm "$fx/docs/missing.md"
g -C "$fx" rm --quiet --cached docs/missing.md

add_case private '[the log](DECISIONS.md)'
run_cmd check_links "$fx" "$list"
t_check "a link to an untracked file that exists on disk fails" rc_nonzero
t_check "and names it" out_has "docs/private.md: DECISIONS.md is not a tracked file (docs/DECISIONS.md)"
rm "$fx/docs/private.md"
g -C "$fx" rm --quiet --cached docs/private.md

add_case outside '[up](../../../etc/passwd)'
run_cmd check_links "$fx" "$list"
t_check "a link that leaves the repository fails" rc_nonzero
t_check "and says so" out_has "leaves the repository"
rm "$fx/docs/outside.md"
g -C "$fx" rm --quiet --cached docs/outside.md

add_case fragment '[bad](missing.md#section)'
run_cmd check_links "$fx" "$list"
t_check "a fragment does not hide a missing file" rc_nonzero
rm "$fx/docs/fragment.md"
g -C "$fx" rm --quiet --cached docs/fragment.md

add_case refdef '[ref]: gone.md'
run_cmd check_links "$fx" "$list"
t_check "a reference definition is checked" rc_nonzero
rm "$fx/docs/refdef.md"
g -C "$fx" rm --quiet --cached docs/refdef.md

# README.md's own link to the untracked symlinked file, as README.md:5 had it.
printf '%s\n' '[decisions](docs/DECISIONS.md)' >>"$fx/README.md"
g -C "$fx" add README.md
g -C "$fx" ls-files >"$list"
run_cmd check_links "$fx" "$list"
t_check "a link to a private file that is a symlink on this disk fails, as README.md and docs/CLI.md did" rc_nonzero
t_check "and names README.md" out_has "README.md: docs/DECISIONS.md is not a tracked file"

# --- the real repository --------------------------------------------------------------------------
git -C "$repo" ls-files >"$list"
run_cmd check_links "$repo" "$list"
if [ "$RC" -ne 0 ]; then
  cat "$OUT" >&2
fi
t_check "every relative link in a tracked Markdown file of this repository resolves to a tracked file" rc_is 0

t_finish
