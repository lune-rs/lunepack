#!/bin/sh
# The shell app of the end-to-end suite (M5 step 14): the same app as examples/e2e_app.rs, written
# against the runtime's command line only (docs/RUNTIME.md). POSIX sh: no bashisms, no jq.
#
# At every start it runs `startup --json -- "$@"` first and exits when the action is "exit"; then
# it acts on the marker file `e2e-flags` at its tree's root (crash-on-start, exit-without-confirm,
# slow-confirm <secs>), confirms its health, and with `--update` runs check, download and
# apply-and-restart (with `--no-ui` as well, the call carries `--no-ui`: no update window).
# Outcomes go to the file LUNEPACK_E2E_OUT as `<tree version> <outcome>`, the executable's real
# path to LUNEPACK_E2E_DETAIL (neither is written when its variable is unset).
#
# Every runtime call is captured by a substitution of two commands (see `call`), so the caller of
# the runtime is a subshell that exits at once: apply-and-restart therefore names this script's
# own pid with --wait-pid (docs/RUNTIME.md, P8).

self=$(readlink -f "$0") || self=
dir=${self%/*}
runtime=$dir/lunepack-runtime
version=-

out() {
    [ -n "${LUNEPACK_E2E_OUT:-}" ] || return 0
    printf '%s %s\n' "$version" "$1" >>"$LUNEPACK_E2E_OUT"
}

detail() {
    [ -n "${LUNEPACK_E2E_DETAIL:-}" ] || return 0
    printf '%s %s\n' "$version" "$1" >>"$LUNEPACK_E2E_DETAIL"
}

# Runs the runtime with the arguments, captured by a substitution of two commands. Sets rc (the
# exit code) and last (the final non-empty line of stdout, the result or error object).
call() {
    raw=$("$runtime" "$@"; printf '\nrc=%s\n' "$?")
    rc=${raw##*rc=}
    body=${raw%rc=*}
    last=$(printf '%s\n' "$body" | grep -v '^$' | tail -n 1)
}

# The value of a string member of the last object, empty when it is absent or null.
member() {
    printf '%s' "$last" | sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'
}

if [ ! -x "$runtime" ]; then
    out "error locate"
    exit 1
fi

call startup --json -- "$@"
version=$(member tree_version)
[ -n "$version" ] || version=-
if [ "$rc" != 0 ]; then
    out "error startup"
    exit 1
fi
startup=$last

detail "exe $self"
out "start"

update=
noui=
for arg in "$@"; do
    case $arg in
        --after-update) out "arg after-update" ;;
        --update) update=1 ;;
        --no-ui) noui=--no-ui ;;
    esac
done

# The events, oldest first: one per object of the array.
events=${startup#*'"events":['}
events=${events%%'],"action"'*}
printf '%s' "$events" | tr '}' '\n' | while IFS= read -r event; do
    case $event in
        *'"kind":"installed"'*) out "event installed" ;;
        *'"kind":"first_run"'*) out "event first_run" ;;
        *'"kind":"updated"'*)
            from=$(printf '%s' "$event" | sed -n 's/.*"from":"\([^"]*\)".*/\1/p')
            out "event updated $from"
            ;;
    esac
done

case $startup in
    *'"action":"exit"'*)
        out "exit rolled-back"
        exit 0
        ;;
esac

# The tree's root: the nearest directory above this one that holds the update configuration.
tree=$dir
while [ ! -f "$tree/lunepack-update.json" ]; do
    [ -n "$tree" ] || break
    tree=${tree%/*}
done

crash=
noconfirm=
slow=
if [ -n "$tree" ] && [ -f "$tree/e2e-flags" ]; then
    while IFS=' ' read -r word rest; do
        case $word in
            crash-on-start) crash=1 ;;
            exit-without-confirm) noconfirm=1 ;;
            slow-confirm) slow=$rest ;;
        esac
    done <"$tree/e2e-flags"
fi
case $slow in
    *[!0-9]*) slow= ;;
esac

if [ -n "$crash" ]; then
    out "crash"
    exit 3
fi
if [ -n "$noconfirm" ]; then
    out "exit-without-confirm"
    exit 0
fi
if [ -n "$slow" ]; then
    out "slow-confirm"
    sleep "$slow"
fi

call confirm --json
case $rc in
    0)
        case $last in
            *'"outcome":"confirmed"'*) out "confirmed" ;;
            *'"outcome":"nothing_pending"'*) out "nothing-pending" ;;
            *)
                out "error confirm"
                exit 1
                ;;
        esac
        ;;
    16)
        out "error token-mismatch"
        exit 1
        ;;
    *)
        out "error confirm"
        exit 1
        ;;
esac

[ -n "$update" ] || exit 0

call check --json
if [ "$rc" != 0 ]; then
    out "error check"
    exit 1
fi
case $last in
    *'"update":null'*)
        out "check none"
        exit 0
        ;;
esac
found=$(printf '%s' "$last" | sed -n 's/.*"update":{"version":"\([^"]*\)".*/\1/p')
if [ -z "$found" ]; then
    out "error check"
    exit 1
fi
out "check $found"

call download --json --expect-version "$found"
staged=$(printf '%s' "$last" | sed -n 's/.*"version":"\([^"]*\)","staged":true.*/\1/p')
if [ "$rc" != 0 ] || [ -z "$staged" ]; then
    out "error download"
    exit 1
fi
out "staged $staged"

# $noui is empty or one word, so it is left unquoted on purpose.
# shellcheck disable=SC2086
call apply-and-restart --json --wait-pid $$ --expect-version "$staged" $noui -- --after-update
if [ "$rc" != 0 ]; then
    out "error apply"
    exit 1
fi
out "apply-scheduled"
exit 0
