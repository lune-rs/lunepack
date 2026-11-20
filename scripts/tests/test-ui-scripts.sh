#!/usr/bin/env bash
# Tests for scripts/ui-golden.sh (argument handling only: nothing here starts Docker or a render),
# scripts/macos-user-check.sh (its arguments and refusals only: nothing here builds or opens anything)
# and scripts/ci/ui-size.sh (its arguments, and its fail-closed reading of the packager's output,
# with a stub in place of the `lunepack` command).
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
GOLDEN=$here/../ui-golden.sh
SIZE=$here/../ci/ui-size.sh
USER_CHECK=$here/../macos-user-check.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

# --- ui-golden.sh ---------------------------------------------------------------------------
run_cmd bash "$GOLDEN" --bogus
t_check "an unknown option is a usage error" rc_is 2
t_check "usage is printed" out_has "usage:"

run_cmd bash "$GOLDEN" extra
t_check "a stray argument is a usage error" rc_is 2

run_cmd bash "$GOLDEN" --write
t_check "--write without --docker is a usage error (goldens come from the reference image only)" rc_is 2

run_cmd bash "$GOLDEN" --help
t_check "--help exits 0" rc_is 0
t_check "--help prints usage" out_has "usage:"

# --- ui-size.sh -----------------------------------------------------------------------------
run_cmd bash "$SIZE"
t_check "no arguments is a usage error" rc_is 2

run_cmd bash "$SIZE" one two three four
t_check "too many arguments is a usage error" rc_is 2

: >"$T_TMP/empty"
printf 'binary' >"$T_TMP/ui"
printf '#!/bin/sh\nexit 0\n' >"$T_TMP/cli-noop"
chmod +x "$T_TMP/cli-noop"

run_cmd bash "$SIZE" "$T_TMP/nowhere" "$T_TMP/cli-noop"
t_check "a missing binary fails" rc_is 1
t_check "it says what is missing" out_has "not a file"

run_cmd bash "$SIZE" "$T_TMP/empty" "$T_TMP/cli-noop"
t_check "an empty binary fails closed" rc_is 1
t_check "it says the binary is empty" out_has "empty"

run_cmd bash "$SIZE" "$T_TMP/ui" "$T_TMP/nowhere"
t_check "a missing lunepack command fails" rc_is 1

# A stub that prints what the real one does, with the totals line the test chooses.
stub() { # <totals line or empty>
  cat >"$T_TMP/cli" <<EOF
#!/bin/sh
case "\$1 \$2" in
  "keys gen") echo "public: aaaa"; echo "wrote the private key" >&2 ;;
  "init --app-id") ;;
  "keys set") ;;
  "pack --input")
    echo "hash: 1 file(s), 0 dir(s), 0 symlink(s), 6 bytes"
    $1
    echo "codec lzma2: 1"
    ;;
esac
exit 0
EOF
  chmod +x "$T_TMP/cli"
}

stub 'echo "totals: 1 file(s), 6 input bytes, 40 pack bytes"'
run_cmd bash "$SIZE" "$T_TMP/ui" "$T_TMP/cli" "$T_TMP/summary.md"
t_check "a readable packager output is a pass" rc_is 0
t_check "it reports the raw size" out_has "raw 6 bytes"
t_check "it reports the frame length the packager chose" out_has "frame 40 bytes"
t_check "it names the codec" out_has "lzma2"
t_check "the summary table row is appended" grep -q '| 6 | 40 | lzma2 |' "$T_TMP/summary.md"

stub 'echo "something else"'
run_cmd bash "$SIZE" "$T_TMP/ui" "$T_TMP/cli"
t_check "no totals line fails closed" rc_is 1
t_check "it says the totals could not be read" out_has "could not read the totals"

stub 'echo "totals: 1 file(s), 7 input bytes, 40 pack bytes"'
run_cmd bash "$SIZE" "$T_TMP/ui" "$T_TMP/cli"
t_check "an input size that is not the binary's fails closed" rc_is 1

stub 'echo "totals: 1 file(s), 6 input bytes, 0 pack bytes"'
run_cmd bash "$SIZE" "$T_TMP/ui" "$T_TMP/cli"
t_check "an empty frame fails closed" rc_is 1

# --- macos-user-check.sh --------------------------------------------------------------------
run_cmd bash "$USER_CHECK" --bogus
t_check "user check: an unknown option is a usage error" rc_is 2
t_check "user check: usage is printed" out_has "usage:"

run_cmd bash "$USER_CHECK" extra
t_check "user check: a stray argument is a usage error" rc_is 2

run_cmd bash "$USER_CHECK" --no-gui --real-applications
t_check "user check: --no-gui with --real-applications is a usage error" rc_is 2

run_cmd bash "$USER_CHECK" --help
t_check "user check: --help exits 0" rc_is 0
t_check "user check: --help prints usage" out_has "usage:"

if [ "$(uname -s)" != Darwin ]; then
  run_cmd bash "$USER_CHECK"
  t_check "user check: a run off macOS is refused" rc_is 1
  t_check "user check: the refusal says macOS only" out_has "macOS only"
else
  # No terminal on the output (run_cmd redirects it): the walk asks questions, so it refuses
  # before it builds anything or makes its root.
  before=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'lunepack-usercheck.*' 2>/dev/null | wc -l | tr -d ' ')
  run_cmd bash "$USER_CHECK"
  t_check "user check: a run without a terminal is refused" rc_is 1
  t_check "user check: the refusal names the terminal" out_has "without a terminal"
  after=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'lunepack-usercheck.*' 2>/dev/null | wc -l | tr -d ' ')
  t_check "user check: the refusal made no temporary root" test "$before" = "$after"
  run_cmd bash "$USER_CHECK" --real-applications
  t_check "user check: --real-applications without a terminal is refused too" rc_is 1
fi

t_finish
