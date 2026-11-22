#!/usr/bin/env bash
# Throwaway code-signing identities for the macOS end-to-end suite (M9 step 9), CI runners only.
#
#   scripts/ci/macos-selfsigned.sh create <dir>   makes <dir> (it must not exist), a temporary
#                                                 keychain in it and two self-signed code-signing
#                                                 identities in that keychain; prints
#                                                 LUNEPACK_E2E_KEYCHAIN=, LUNEPACK_E2E_IDENTITY_A=
#                                                 and LUNEPACK_E2E_IDENTITY_B= (a path and two
#                                                 certificate names: none of them is a secret)
#   scripts/ci/macos-selfsigned.sh delete <dir>   deletes the keychain, undoes what `create` added
#                                                 to a trust store and removes <dir>
#
# The identities exist for the length of one job: random names, a random keychain password that is
# only a shell variable, a 2-day certificate, a key that is generated here and never leaves <dir>.
# Nothing is committed, nothing comes from a workflow secret. The keychain is NEVER added to the
# user's search list (the list is read before and after `create` and put back if it changed) and
# never becomes the default keychain; the suite names it with `codesign --keychain`.
#
# Refuses to run unless CI is `true`: on a developer's Mac the suite runs without the identities
# (ad hoc only, `scripts/e2e-macos.sh` without --ci). If the runner refuses the identity by name
# ("no identity found" even with the keychain named; an untrusted self-signed certificate is the
# likely reason, not verified), `create` prints what `security find-identity` says of the keychain
# and tries the certificate's SHA-1 hash instead (codesign(1): forty hexadecimal digits name the
# identity by its certificate hash and the subject name is not considered); when that signs, the
# printed LUNEPACK_E2E_IDENTITY_* is the hash (the suites pass it to codesign --sign as it is, and
# the publisher rows take names or hashes). Only when the hash cannot sign
# either does it try to add trust for the certificate (user domain, then the admin domain through
# sudo -n, both only on CI), recording what it added so `delete` removes it. Changing trust settings
# needs an authorization (`security authorizationdb read com.apple.trust-settings.user`: the session
# owner authenticates; `...admin`: an administrator authenticates, root not allowed), which on a
# runner is a prompt nobody answers: CI run 44987455165 waited in the first add-trusted-cert until
# the job's 90-minute timeout. So every security and codesign call here is bounded (`bounded`,
# below) and a timed-out one says so and fails; after one trust attempt timed out no other is made.
# If the identity still cannot sign, `create` fails with a line starting "INVALID:" and the job
# fails: a continuity row cannot pass without a real identity.
# bash 3.2 compatible.
set -euo pipefail

usage() {
  echo "usage: scripts/ci/macos-selfsigned.sh create <dir> | delete <dir>" >&2
}

die() {
  echo "macos-selfsigned: $*" >&2
  exit 1
}

[ "$(uname -s)" = Darwin ] || die "refusing to run: macOS only"
[ "${CI:-}" = true ] || die "refusing to run off CI (CI is not 'true'): the suite runs ad hoc only on a developer's Mac"
[ "$(id -u)" != 0 ] || die "refusing to run as root"

security=/usr/bin/security
codesign=/usr/bin/codesign
openssl=/usr/bin/openssl
marker=.lunepack-e2e-identities

# Seconds a codesign or find-identity call, and a trust change, may take before it is stopped.
sign_limit=60
trust_limit=30

# Runs "$@" with stdin closed and at most $1 seconds; returns its exit status, or 124 after
# stopping it (TERM, then KILL) when it took longer. Nothing on a runner answers a prompt, so a call
# that waits for one is stopped instead of hanging the job.
bounded() {
  local limit=$1 pid ticks=0 status=0
  shift
  "$@" </dev/null &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$ticks" -ge $((limit * 5)) ]; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 0.2
    ticks=$((ticks + 1))
  done
  wait "$pid" || status=$?
  return "$status"
}

# The user's keychain search list, one path per line (quotes and indentation removed).
search_list() {
  "$security" list-keychains -d user 2>/dev/null | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//'
}

# Puts the search list back to the lines of $1 (a file) when it differs from it.
restore_search_list() {
  local saved=$1 now
  now=$(search_list)
  if [ "$now" = "$(cat "$saved")" ]; then
    return 0
  fi
  echo "macos-selfsigned: the search list changed; putting it back" >&2
  local paths=() line
  while IFS= read -r line; do
    [ -n "$line" ] && paths+=("$line")
  done <"$saved"
  if [ "${#paths[@]}" -gt 0 ]; then
    "$security" list-keychains -d user -s "${paths[@]}" >/dev/null
  fi
  [ "$(search_list)" = "$(cat "$saved")" ] || die "could not put the keychain search list back"
}

# One self-signed code-signing certificate and key in $dir (files a.c/a.k, no key-container name),
# imported into the keychain as an identity named $2.
make_identity() {
  local dir=$1 name=$2 tag=$3 keychain=$4 password=$5
  cat >"$dir/$tag.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $name
[ext]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
EOF
  "$openssl" req -x509 -newkey rsa:2048 -nodes -days 2 -config "$dir/$tag.cnf" \
    -keyout "$dir/$tag.k" -out "$dir/$tag.c" 2>/dev/null
  P12_PASSWORD=$password "$openssl" pkcs12 -export -inkey "$dir/$tag.k" -in "$dir/$tag.c" \
    -name "$name" -out "$dir/$tag.id" -passout env:P12_PASSWORD
  "$security" import "$dir/$tag.id" -k "$keychain" -f pkcs12 -P "$password" \
    -T "$codesign" -T "$security" >/dev/null
  rm -f "$dir/$tag.k" "$dir/$tag.id" "$dir/$tag.cnf"
}

# Whether $identity (a name or a SHA-1 hash) signs a copy of a system binary (a probe in $dir; the
# copy is removed).
can_sign() {
  local dir=$1 keychain=$2 identity=$3 status=0
  cp /usr/bin/true "$dir/probe"
  bounded "$sign_limit" "$codesign" --force --sign "$identity" --keychain "$keychain" --timestamp=none "$dir/probe" >"$dir/probe.log" 2>&1 || status=$?
  if [ "$status" = 0 ]; then
    bounded "$sign_limit" "$codesign" --verify --strict "$dir/probe" >>"$dir/probe.log" 2>&1 || status=$?
  fi
  if [ "$status" = 0 ]; then
    rm -f "$dir/probe" "$dir/probe.log"
    return 0
  fi
  [ "$status" != 124 ] || echo "codesign did not finish within $sign_limit s; stopped" >>"$dir/probe.log"
  # The tool's first lines say why ("no identity found", a keychain error); the name is not secret.
  sed -e 's/^/macos-selfsigned: codesign: /' "$dir/probe.log" | head -3 >&2
  rm -f "$dir/probe" "$dir/probe.log"
  return 1
}

# The SHA-1 hash of the certificate $1 (40 hexadecimal digits, upper case), the form codesign takes
# as an identity without a name lookup.
cert_hash() {
  "$openssl" x509 -in "$1" -noout -fingerprint -sha1 | sed -e 's/^.*=//' -e 's/://g' | tr '[:lower:]' '[:upper:]'
}

# What the keychain's code-signing identities look like to Security (names, hashes and the reason
# one is not valid; none of it is secret), to stderr.
show_identities() {
  local dir=$1 keychain=$2 status=0
  bounded "$sign_limit" "$security" find-identity -p codesigning "$keychain" >"$dir/find.log" 2>&1 || status=$?
  [ "$status" != 124 ] || echo "find-identity did not finish within $sign_limit s; stopped" >>"$dir/find.log"
  sed -e 's/^/macos-selfsigned: find-identity: /' "$dir/find.log" | head -8 >&2
  rm -f "$dir/find.log"
}

# Adds trust for the certificate $dir/$tag.c in $domain (user or admin), bounded; records it in
# $dir/trust-$tag when added. Returns 0 (added), 1 (refused) or 124 (stopped: it waited for an
# authorization nobody can give).
add_trust() {
  local dir=$1 tag=$2 domain=$3 status=0
  case $domain in
    user) bounded "$trust_limit" "$security" add-trusted-cert -r trustRoot -p codeSign "$dir/$tag.c" >/dev/null 2>&1 || status=$? ;;
    admin) bounded "$trust_limit" sudo -n "$security" add-trusted-cert -d -r trustRoot -p codeSign "$dir/$tag.c" >/dev/null 2>&1 || status=$? ;;
  esac
  if [ "$status" = 0 ]; then
    echo "$domain" >"$dir/trust-$tag"
    return 0
  fi
  if [ "$status" = 124 ]; then
    echo "macos-selfsigned: adding trust in the $domain domain waited $trust_limit s for an authorization nobody can give; stopped it" >&2
    return 124
  fi
  echo "macos-selfsigned: adding trust in the $domain domain was refused (exit $status)" >&2
  return 1
}

create() {
  local dir=$1
  [ ! -e "$dir" ] || die "$dir exists: refusing to reuse a directory"
  mkdir -p "$dir"
  chmod 700 "$dir"
  : >"$dir/$marker"
  search_list >"$dir/search-list"
  local keychain=$dir/lunepack-e2e.keychain-db
  local ok=0
  # Anything that fails from here on removes what was made.
  trap '[ "$ok" = 1 ] || delete "$dir" >/dev/null 2>&1 || true' EXIT

  local hex password
  hex=$("$openssl" rand -hex 4)
  password=$("$openssl" rand -hex 16)
  "$security" create-keychain -p "$password" "$keychain"
  restore_search_list "$dir/search-list"
  "$security" set-keychain-settings -t 7200 "$keychain"
  "$security" unlock-keychain -p "$password" "$keychain"

  local name_a="lunepack-e2e-a-$hex" name_b="lunepack-e2e-b-$hex"
  make_identity "$dir" "$name_a" a "$keychain" "$password"
  make_identity "$dir" "$name_b" b "$keychain" "$password"
  # Lets codesign use the keys without a prompt (nobody is there to answer one).
  "$security" set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null 2>&1 ||
    die "INVALID: the key partition list could not be set; codesign would prompt for the key"
  restore_search_list "$dir/search-list"

  # What each identity is passed to codesign as: its name, or its certificate's hash.
  local use_a=$name_a use_b=$name_b
  local identity tag name hash use trust_stopped=0 domain status
  for identity in "$name_a:a" "$name_b:b"; do
    tag=${identity#*:}
    name=${identity%%:*}
    use=
    if can_sign "$dir" "$keychain" "$name"; then
      use=$name
    else
      show_identities "$dir" "$keychain"
      hash=$(cert_hash "$dir/$tag.c")
      echo "macos-selfsigned: $name is refused by name; trying its certificate's SHA-1 hash $hash" >&2
      if can_sign "$dir" "$keychain" "$hash"; then
        use=$hash
      elif [ "$trust_stopped" = 1 ]; then
        echo "macos-selfsigned: not adding trust for $name: an earlier attempt waited for an authorization" >&2
      else
        echo "macos-selfsigned: $name cannot sign untrusted; adding trust (CI only)" >&2
        for domain in user admin; do
          status=0
          add_trust "$dir" "$tag" "$domain" || status=$?
          [ "$status" != 0 ] || break
          if [ "$status" = 124 ]; then
            trust_stopped=1
            break
          fi
        done
        if [ -f "$dir/trust-$tag" ]; then
          if can_sign "$dir" "$keychain" "$name"; then
            use=$name
          elif can_sign "$dir" "$keychain" "$hash"; then
            use=$hash
          fi
        fi
      fi
    fi
    [ -n "$use" ] ||
      die "INVALID: the runner refuses the throwaway identity $name (by name and by hash): the continuity rows cannot run"
    echo "macos-selfsigned: $name signs as: $use" >&2
    case $tag in
      a) use_a=$use ;;
      b) use_b=$use ;;
    esac
  done
  restore_search_list "$dir/search-list"

  ok=1
  echo "LUNEPACK_E2E_KEYCHAIN=$keychain"
  echo "LUNEPACK_E2E_IDENTITY_A=$use_a"
  echo "LUNEPACK_E2E_IDENTITY_B=$use_b"
}

delete() {
  local dir=$1
  [ -d "$dir" ] && [ -f "$dir/$marker" ] || die "$dir is not a directory this script made: refusing to delete it"
  local keychain=$dir/lunepack-e2e.keychain-db tag
  for tag in a b; do
    if [ -f "$dir/trust-$tag" ] && [ -f "$dir/$tag.c" ]; then
      case $(cat "$dir/trust-$tag") in
        user) bounded "$trust_limit" "$security" remove-trusted-cert "$dir/$tag.c" >/dev/null 2>&1 || true ;;
        admin) bounded "$trust_limit" sudo -n "$security" remove-trusted-cert -d "$dir/$tag.c" >/dev/null 2>&1 || true ;;
      esac
    fi
  done
  if [ -e "$keychain" ]; then
    "$security" delete-keychain "$keychain" >/dev/null 2>&1 || true
  fi
  if [ -f "$dir/search-list" ]; then
    restore_search_list "$dir/search-list" || true
  fi
  rm -rf "$dir"
}

[ "$#" -eq 2 ] || {
  usage
  exit 2
}
case $1 in
  create) create "$2" ;;
  delete) delete "$2" ;;
  *)
    usage
    exit 2
    ;;
esac
