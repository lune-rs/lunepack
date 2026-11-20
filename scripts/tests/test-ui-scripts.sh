#!/usr/bin/env bash
# Tests for scripts/ui-golden.sh (argument handling only: nothing here starts Docker or a render),
# scripts/macos-user-check.sh (its arguments and refusals only: nothing here builds or opens anything)
# scripts/macos-sign-check.sh (its arguments and its credential refusals only: nothing here builds,
# signs or contacts a service) and scripts/ci/ui-size.sh (its arguments, and its fail-closed reading of the packager's output,
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
SIGN_CHECK=$here/../macos-sign-check.sh
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

# --- macos-sign-check.sh --------------------------------------------------------------------
run_cmd bash "$SIGN_CHECK" --bogus
t_check "sign check: an unknown option is a usage error" rc_is 2
t_check "sign check: usage is printed" out_has "usage:"

run_cmd bash "$SIGN_CHECK" extra
t_check "sign check: a stray argument is a usage error" rc_is 2

run_cmd bash "$SIGN_CHECK" --windows-note --dry-run
t_check "sign check: --windows-note with --dry-run is a usage error" rc_is 2

run_cmd bash "$SIGN_CHECK" --help
t_check "sign check: --help exits 0" rc_is 0
t_check "sign check: --help prints usage" out_has "usage:"

run_cmd bash "$SIGN_CHECK" --windows-note
t_check "sign check: --windows-note exits 0 on any OS" rc_is 0
t_check "sign check: --windows-note says it is not run here" out_has "not here"

if [ "$(uname -s)" != Darwin ]; then
  run_cmd bash "$SIGN_CHECK" --dry-run
  t_check "sign check: a run off macOS is refused" rc_is 1
  t_check "sign check: the refusal says macOS only" out_has "macOS only"
else
  # The planted values must never appear in any output: they stand for an identity name, a key id,
  # an issuer and a key path.
  planted_identity=PLANTED-IDENTITY-0xD3ADB33F
  planted_key_id=PLANTEDKEYID7Q
  planted_issuer=PLANTED-ISSUER-5b7e
  keys=$T_TMP/planted-keys-dir
  mkdir -p "$keys"
  printf 'not a key\n' >"$keys/planted-key-file"
  chmod 600 "$keys/planted-key-file"
  roots_before=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'lunepack-signcheck.*' 2>/dev/null | wc -l | tr -d ' ')
  sign_env() { # <identity> <key> <key id> <issuer>: every credential variable, set or not
    env -u LUNEPACK_SIGN_IDENTITY -u LUNEPACK_NOTARY_KEY -u LUNEPACK_NOTARY_KEY_ID -u LUNEPACK_NOTARY_ISSUER \
      ${1:+LUNEPACK_SIGN_IDENTITY="$1"} ${2:+LUNEPACK_NOTARY_KEY="$2"} \
      ${3:+LUNEPACK_NOTARY_KEY_ID="$3"} ${4:+LUNEPACK_NOTARY_ISSUER="$4"} \
      bash "$SIGN_CHECK"
  }
  planted_absent() {
    ! grep -qF -e "$planted_identity" -e "$planted_key_id" -e "$planted_issuer" -e "planted-key" "$OUT"
  }

  run_cmd sign_env "" "" "" ""
  t_check "sign check: no variable set is refused" rc_is 1
  t_check "sign check: it names LUNEPACK_SIGN_IDENTITY" out_has "LUNEPACK_SIGN_IDENTITY is not set"
  t_check "sign check: it names LUNEPACK_NOTARY_KEY" out_has "LUNEPACK_NOTARY_KEY is not set"
  t_check "sign check: it names LUNEPACK_NOTARY_KEY_ID" out_has "LUNEPACK_NOTARY_KEY_ID is not set"
  t_check "sign check: it names LUNEPACK_NOTARY_ISSUER" out_has "LUNEPACK_NOTARY_ISSUER is not set"

  run_cmd sign_env "$planted_identity" "$keys/planted-key-file" "" "$planted_issuer"
  t_check "sign check: one missing variable is refused" rc_is 1
  t_check "sign check: it names the one that is missing" out_has "LUNEPACK_NOTARY_KEY_ID is not set"
  t_check "sign check: it does not name the ones that are set" out_lacks "LUNEPACK_SIGN_IDENTITY is not set"
  t_check "sign check: no planted value in the output (one missing)" planted_absent

  chmod 644 "$keys/planted-key-file"
  run_cmd sign_env "$planted_identity" "$keys/planted-key-file" "$planted_key_id" "$planted_issuer"
  t_check "sign check: a key file of mode 0644 is refused" rc_is 1
  t_check "sign check: the refusal names the mode and the variable" out_has "LUNEPACK_NOTARY_KEY is not mode 0600"
  t_check "sign check: no planted value in the output (mode 0644)" planted_absent
  chmod 600 "$keys/planted-key-file"

  run_cmd sign_env "$planted_identity" "$keys/planted-no-such-file" "$planted_key_id" "$planted_issuer"
  t_check "sign check: a key path that names nothing is refused" rc_is 1
  t_check "sign check: no planted value in the output (no such file)" planted_absent

  mkdir -p "$keys/planted-dir-as-key"
  run_cmd sign_env "$planted_identity" "$keys/planted-dir-as-key" "$planted_key_id" "$planted_issuer"
  t_check "sign check: a directory as the key path is refused" rc_is 1
  t_check "sign check: it says not a regular file" out_has "not a regular file"

  ln -s "$keys/planted-key-file" "$keys/planted-link"
  run_cmd sign_env "$planted_identity" "$keys/planted-link" "$planted_key_id" "$planted_issuer"
  t_check "sign check: a link as the key path is refused" rc_is 1
  t_check "sign check: no planted value in the output (link)" planted_absent

  # A key inside a git checkout (a repository made here, with the repo's own refusal rule).
  g init -q "$T_TMP/planted-repo"
  mkdir -p "$T_TMP/planted-repo/sub"
  printf 'not a key\n' >"$T_TMP/planted-repo/sub/planted-key-file"
  chmod 600 "$T_TMP/planted-repo/sub/planted-key-file"
  run_cmd sign_env "$planted_identity" "$T_TMP/planted-repo/sub/planted-key-file" "$planted_key_id" "$planted_issuer"
  t_check "sign check: a key inside a git checkout is refused" rc_is 1
  t_check "sign check: the refusal says so" out_has "inside a git checkout"
  t_check "sign check: no planted value in the output (inside a checkout)" planted_absent

  # A key inside this repository (the worktree the script runs from).
  repo_probe=$(mktemp -d "$here/../../.signcheck-test.XXXXXX")
  printf 'not a key\n' >"$repo_probe/planted-key-file"
  chmod 600 "$repo_probe/planted-key-file"
  run_cmd sign_env "$planted_identity" "$repo_probe/planted-key-file" "$planted_key_id" "$planted_issuer"
  rm -rf "$repo_probe"
  t_check "sign check: a key inside this repository is refused" rc_is 1
  t_check "sign check: the refusal says so (repository)" out_has "inside"
  t_check "sign check: no planted value in the output (inside this repository)" planted_absent

  roots_after=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'lunepack-signcheck.*' 2>/dev/null | wc -l | tr -d ' ')
  t_check "sign check: every refusal came before the temporary root was made" test "$roots_before" = "$roots_after"
fi

t_finish
