# The runtime's command line

Every version tree of an app that updates itself carries `lunepack-runtime`, placed beside the
app's entry executable by `lunepack pack --runtime` (`docs/CLI.md`). Besides the internal modes it
runs for the installer and the applier, it is a command line that an app in any language runs as a
child process to check for an update, download it, learn what happened since its last start,
confirm that it works and hand a staged update over to be applied. Each command is a thin layer over
the library calls a Rust app makes (`Updater::check`, `download` and `stage`, `startup`,
`confirm_healthy`, `apply_and_restart`), so both get the same behaviour and the same errors (D42).
`docs/INTEGRATION.md` walks through the command line with a .NET app and real output; a Rust app starts
from `docs/GETTING-STARTED.md`. The decisions are M5-D11 and M5-D12 in `docs/DECISIONS.md`;
what the output must never hold is in `docs/THREAT-MODEL.md` ("The Linux runtime").

## Locating the runtime

The runtime is `lunepack-runtime` in the same directory as the app's entry executable (the
`install.entry` of `lunepack.toml`). An app finds it from its own resolved executable path
(`readlink -f "$0"` in a shell script), never through `current`, a shortcut, a command link or
`PATH`. It finds its tree by walking up from its own directory to the nearest
`lunepack-update.json` (`docs/FORMAT.md` 13), which holds the app id, the trusted root, the feed and
the channel: no argument supplies any of them. The feed must pass the feed rule of `docs/FORMAT.md`
13.3 (`https:`, `file:`, or `http:` to a loopback address only).

Where the install root `R` is depends on the OS, and an app must never compute it: it takes it from the
facade (`Installation`) or from its own resolved path, never by joining the data home with a name. On
Linux `R` is `<data home>/<app id>` with the trees in `versions/<version>/`. On Windows `R` is a folder of
the per-user programs folder (by default `%LOCALAPPDATA%\Programs`) named after the app's display name at
its first install, kept for the life of the install, with the trees in `app\<version>\` and the runtime's
state under a hidden `.lunepack\` (`docs/FORMAT.md` 16). An app on Windows finds its runtime as
`lunepack-runtime.exe` beside its entry, from its own resolved executable path
(`GetModuleFileNameW`), never from the stub's path at `R`: the stub is a launcher, not the app. On macOS `R`
is `<data home>/<app id>` with the data home `~/Library/Application Support`, the trees of kept versions are
in `versions/<version>/`, and the app itself is a bundle `B` in `~/Applications` that `R/bundle` points at; an
app finds its runtime as `lunepack-runtime` in `Contents/MacOS` beside its entry, from its own resolved
executable path, and the configuration it reads is `Contents/Resources/lunepack-update.json` of that bundle
(`docs/FORMAT.md` 17, and "macOS" below). On a per-machine install `R` is `<Program Files>\<name>` on Windows
(above), `/opt/<app id>` on Linux and `/Library/Application Support/lunepack/<app id>` on macOS, with the trees in
`app/<version>/` (on macOS the live bundle `B` is in `/Applications`; `docs/FORMAT.md` 18 and 20). The rule for
finding the runtime does not change: the app's own resolved executable path, never the link `R/current`, the command
link or the desktop entry, which go through `current` for people.

A runtime speaks exactly one schema version, and a runtime belongs to one version tree (D28): every
final object names that tree in `tree_version`, so an app can tell when it reached another version's
runtime.

## Command line

```
lunepack-runtime <command> [options] [-- <args>]
```

| Command | Options | What it does |
|---|---|---|
| `check` | `--channel <name>` | Looks for an update on the channel. |
| `download` | `--channel <name>`, `--expect-version <version>` | Runs `check`, then downloads and stages the update it found. |
| `startup` | `-- <args>` | Delivers the lifecycle events queued for this version and says whether to go on. |
| `confirm` | none | Confirms that this version works. |
| `apply-and-restart` | `--wait-pid <pid>`, `--expect-version <version>`, `--no-ui`, `--background`, `-- <args>` | Starts the applier for the staged version, which applies it and starts the new version with `<args>` once the waited-for process has exited. With `--no-ui` the applier shows no update window. With `--background` (macOS only; no effect elsewhere) the new version is started without being brought to the front. |
| `repair` | `--silent` | (a machine install) Re-creates the update service's registration from the confirmed current version, after one administrator approval; an administrator's own process needs none. On Windows that is the service, its descriptor and its demand start; on Linux the units and the stable service link; on macOS the LaunchDaemon and the link ("Per-machine installs (Linux and macOS, M11)" below). With `--silent`, or where nothing can ask (macOS, Linux without `pkexec`), a standard user's run exits 30 and asks nothing. On any install that is not per machine it is a usage error. |

Global options, accepted by every command: `--json` (output JSON Lines instead of text) and
`--expect-schema <N>` (the schema the caller understands; anything but `1` is the error
`schema_mismatch`, before anything else happens).

The grammar is closed. Every option may appear once; a flag (`--json`, `--no-ui`, `--background`, `--silent`) takes
no value. An unknown option, a repeated one, an option
that does not belong to the command, a value that does not parse (a channel name outside the rule of
`docs/FORMAT.md` 10.5, a version that is not in its canonical text, a number with a sign or leading
zeros, a `--wait-pid` of 0 or 1), a missing value, the `--option=value` form and any stray word are a usage error: exit code 2,
before any action (no lock, no state read, no network). The refusal names nothing of the arguments:
one fixed line on stderr, or, when `--json` stands before any `--`, the `error` object below with
`command` and `tree_version` null. `download` never takes an update description from its caller:
`--expect-version` only names the version the app expects, and any other candidate is the error
`unexpected_version`, never a downgrade.

`startup` takes everything after `--` as the arguments the app was started with. They matter only
when the start rolls back, because the previous version is then started with them.
`apply-and-restart` takes everything after `--` as the arguments the new version is started with
(and, if it rolls back, the previous one).

## Output

With `--json`, stdout holds only UTF-8 JSON Lines, one object per line, each with `"schema":1` and a
`type`. Zero or more `progress` objects come first, then exactly one final object, `result` or
`error`. Changes within schema 1 are additive: a reader ignores members it does not know.

```json
{"schema":1,"type":"progress","phase":"download","done":1048576,"total":5242880,"file":null}
{"schema":1,"type":"progress","phase":"stage","done":7,"total":70,"file":{"path":"bin/app","done":3,"total":9,"source":"range"}}
{"schema":1,"type":"result","command":"download","tree_version":"1.0.0","version":"1.1.0","staged":true}
```

`progress`: `phase` is one of `check`, `scan`, `download`, `stage` and, in a macOS adoption, `adopt` (and, in the runtime's own log,
`install`, `wait`, `apply`, `launch`, `confirm`, `rollback`, `uninstall`); `done` and `total` are
non-negative integers (bytes, 0 when unknown); `file` is null or `{path, done, total, source}` with
`path` the signed relative path and `source` one of `unchanged`, `range`, `full_pack` and (M12, additive within schema 1) `patch`, the file rebuilt from a delta patch. A `scan` phase line may also carry `patch` while the installed file that a patch starts from is hashed; which file ended as a patch is told by the `stage` lines. At most ten
progress lines a second are written, and every phase shows. Without `--json`, progress is at most one
line a second on stderr and the final line is one human line on stdout (an error goes to stderr).

`result` members, after `command` and `tree_version`:

| Command | Members |
|---|---|
| `check` | `update`: `null`, or `{version, download_size_max, time_checked}` (`time_checked` is false when the clock was implausible and expiry checks were skipped); `adopted`: `true`, present only in the run that adopted the running bundle (macOS, "Adoption" below) |
| `download` | `version` and `staged`: the staged version and `true`; or `null` and `false` when the channel offers nothing new; `publisher`: present only when the update was staged with a finding to report, one of `different`, `installed_unsigned`, `installed_invalid`, `candidate_unsigned`, `candidate_invalid`, `os` ("Publisher continuity" below) |
| `startup` | `events`: `[{kind: "installed", version}, {kind: "updated", from, to}, {kind: "first_run", version}, ...]`, oldest first; `action`: `"continue"` or `"exit"`; `pending` |
| `confirm` | `outcome`: `"confirmed"` or `"nothing_pending"` |
| `apply-and-restart` | `version`: the staged version the applier will apply; `scheduled`: `true` |

`error`: `{"schema":1,"type":"error","command":…,"tree_version":…,"kind":…,"exit_code":N}`, with
`command` and `tree_version` null when not known. The strings in any object come only from signed
documents (versions, channel names, relative paths), from the closed sets of this page and from the
build. No stream holds the health token, the install id, key material, a URL, a header, file
contents, an absolute path or the text of an operating-system or network error.

## Exit codes

One code per error class, the same number as in the object's `kind`. They are stable within schema 1.

| Code | `kind` | Meaning |
|---|---|---|
| 0 | | success |
| 2 | `usage` | the command line is outside the grammar |
| 3 | `not_installed` | the tree is not an installed version (a development or bootstrap tree), or there is no install state |
| 4 | `busy` | another lunepack operation holds the install lock, or (a machine install) the update service is serving another connection and did not greet this one in time |
| 5 | `cancelled` | the operation was cancelled, or stdout stopped accepting output |
| 6 | `stale` | the update is no longer applicable |
| 7 | `verify` | a document, hash or signature was refused; on macOS also a bundle that is not byte for byte the release its configuration names (adoption) |
| 8 | `transport` | the feed or pack could not be fetched |
| 9 | `fs` | a filesystem operation failed |
| 10 | `state` | the install state failed or is newer than this build |
| 11 | `incomplete` | a download ended early |
| 12 | `nothing_staged` | nothing usable is staged |
| 13 | `schema_mismatch` | `--expect-schema` names another schema |
| 14 | `update_config` | the tree's update configuration is missing, invalid, or its feed breaks the feed rule |
| 15 | `unexpected_version` | the version found is not the one expected |
| 16 | `token_mismatch` | the health token is malformed or does not match |
| 17 | `machine_scope` | the install is per machine and the operation is not one a per-machine install supports: macOS adoption, and `install` run from inside a machine tree. (On every OS `check`, `download`, `apply-and-restart`, `startup`, `confirm`, `repair` and `uninstall` work on a per-machine install: "Per-machine installs" below) |
| 18 | `unsupported` | not supported on this platform |
| 19 | `process` | a process operation failed |
| 20 | `rolled_back` | (apply) the new version failed its health check and was rolled back |
| 21 | `wait_timeout` | (apply) the process waited for did not exit in time; nothing changed |
| 22 | `rollback_unavailable` | (apply) the previous version cannot be started; the new one stays pending |
| 23 | `already_installed` | (install) the install already has a current version; `current` is linked from its record first, so a run cut off after its commit still ends startable |
| 24 | `integration` | (install, uninstall) the desktop integration failed or is in the way |
| 25 | `in_use` | (uninstall) a process still runs from the install. On macOS a process of the user whose executable file was deleted is judged by its working directory and open files, not by that executable ("macOS" below) |
| 26 | `install_mismatch` | (install, uninstall) the install is not the one this environment derives; for install also an existing `R` that is not lunepack's (not a real directory, or holding files it did not make) |
| 27 | `no_release` | (install) the channel offers no release for this install yet (none, none whose rollout admits it, or none at or above the bootstrap's own version); nothing was installed, retry later. (macOS adoption) the feed lists no release of the version and target the bundle's own configuration names; nothing was adopted |
| 28 | `unsupported_location` | (macOS, every mode) the running app or the install's bundle is somewhere lunepack does not update: the error object carries `reason`, one of `translocated`, `read_only`, `other_volume`, `not_owned`, `not_writable`; move the app to the Applications folder of the user and open it from there |
| 29 | `publisher_mismatch` | (download) the installed version's publisher policy (`enforce`) refused the update: the error object carries `reason`, one of `different`, `installed_invalid`, `candidate_unsigned`, `candidate_invalid`, `os`; nothing was staged. On `different`, `candidate_unsigned` and `candidate_invalid` the version is marked bad and never offered again; on `installed_invalid` and `os` nothing is marked and a later `download` checks again |
| 30 | `elevation_required` | (setup, `repair`, `uninstall`; a per-machine install) the work needs administrator rights, and the run cannot ask for them: Windows, `--all-users --silent` as a standard user; Linux, the same, or no `pkexec` to ask with (the window shows the `sudo` command); macOS, an `uninstall` or `repair` of a standard user (no prompt of our own; the window of `uninstall` shows the `sudo` command); nothing was changed |
| 31 | `elevation_declined` | (setup, `repair`, `uninstall`; a per-machine install) the user declined the administrator prompt (Linux: `pkexec` exit 126); nothing was changed |
| 32 | `service_unavailable` | (a machine install) the update service cannot be used: the error object carries `reason`, one of `not_installed`, `disabled`, `start_failed`, `untrusted`, `timeout`, `protocol`, `unsupported`; the app keeps running its current version. An administrator's `repair` (or re-enabling the service) fixes `not_installed` and `disabled` |
| 33 | `disabled_by_policy` | (a machine install) an administrator's policy switched self-update off; nothing was requested or changed |
| 34 | `per_machine_unavailable` | (setup) the release carries no update service, so it installs per user only |
| 35 | `not_protected` | (setup) a directory of the all-users install is not protected as it must be (Linux and macOS: a folder or an ancestor of `R` that anyone but root may change, or that carries an access control list); nothing was changed |
| 70 | `internal` | anything else (a worker panic, a library error this build does not know) |

The table lives in one place in the runtime (`crates/lunepack-runtime/src/modes.rs`) and is pinned
by `crates/lunepack-runtime/tests/golden/objects.jsonl`, one error object per kind.

## Publisher continuity

An app packed with OS code signing (CLI.md, "Code signing") can refuse an update that a different publisher
signed than the one it is running, so a leaked release key alone does not let an attacker push a build
under another certificate. The check runs when a version is staged (`check` only looks at the feed;
`download` and the facade's `Updater::stage` stage), between staging and recording the staged version, so
every path that turns a candidate into something `apply` can use goes through it. First installs, offline
installs from a setup file, adoption and rollbacks have no installed-and-candidate pair and run no check.

The **policy is the installed version's** `publisher_check` member of its update configuration (FORMAT.md
13.2): `off`, `warn` or `enforce`, absent meaning `off`. The candidate's own member never governs its own
check, and nothing on the command line or in the builder lowers it. A tree with no update configuration
reads as `off`; one that cannot be read fails the staging without marking anything.

What the operating system answers, and what the policy does with it (every pair is covered):

| Answer | `off` | `warn` | `enforce` |
|---|---|---|---|
| same publisher; not applicable (Linux) | proceed | proceed | proceed |
| `installed_unsigned`: the installed version is unsigned or ad-hoc signed, so there is no baseline | proceed | proceed, reported | proceed, reported |
| `different`, `candidate_unsigned`, `candidate_invalid` | proceed | proceed, reported | exit 29, the version is marked bad |
| `installed_invalid`, `os` | proceed | proceed, reported | exit 29, nothing is marked |

`off` runs no check. A refusal that names the candidate's own bytes or signature (`different`,
`candidate_unsigned`, `candidate_invalid`) marks the version bad in the same state commit that skips the
staging: `check` never offers it again (D27) and nothing is staged. `installed_invalid` and `os` are local
faults (a locked file, a broken install, an API failure): nothing is marked, and a later `download` checks
again. `enforce` therefore needs a really signed app: a tree whose files carry no signature of the
platform's kind answers `os` or `candidate_unsigned` and is refused. The packager writes `enforce` only
when the config has a `[codesign.<os>]` section for the target.

A finding that does not stop the update is a `tracing` warning that names the code only, and the optional
`publisher` member of `download`'s result. Neither carries a path, a certificate subject or any text from
the operating system.

The rules, in short (M9-D7, M9-D8): on Windows the installed and the candidate entry executables must both
pass `WinVerifyTrust` (no user interface, no revocation lookup, no network) and their leaf signers' subject
names must be byte-equal, and every other PE file of the candidate must pass under any trusted publisher;
on macOS the candidate bundle must pass a strict, nested static validation and satisfy the installed
bundle's designated requirement (an ad-hoc signature counts as unsigned on either side); Linux has no
check. Only a definitive statement about the candidate's own bytes or signature can mark a version bad: any
other operating-system status, and every file error while reading the tree, is `os`.

On a per-machine install on Windows the check runs inside the update service's engine, between verifying the
upload and recording the staged version, under the installed version's policy exactly as above; a refusal
reaches the caller as exit 29. On a per-machine install on macOS the same check runs in the service's engine (the root daemon wires the macOS check); on Linux it answers "not applicable" there too.

## Apply and restart

`apply-and-restart` reads the staged version again, refuses with `nothing_staged` when nothing
usable is staged and with `unexpected_version` when `--expect-version` names another one, and then
starts the applier: this tree's own runtime in its internal `apply` mode, detached (a new session,
standard streams on `/dev/null`, no health token in its environment). It prints its result and
exits; the app exits next. The applier waits for the process it was given, then applies the update,
starts the new tree's entry (from that tree's own update configuration, without a shell, with the
arguments after `--` and a fresh health token) and supervises its health check (above); its events
go to the runtime's log, `logs/runtime.log` under the install. When the apply fails after the wait
with nothing changed (the new version's configuration is missing or invalid, nothing usable is
staged any more, the version that exited still waits for its own health check, the install lock
stays held, a disk or state error), the applier starts the current version's entry again instead
(detached, with the same arguments, without a health token), so the app that exited for the update
comes back; its exit code is the failure's, in the log. It starts nothing when the install moved on
meanwhile (another version current or pending, or the version to apply marked bad): another
applier, such as a second instance's, or a rollback has started the app already (lunepack marks a
version bad only when it rolls it back, and the rollback starts the previous version). An app that
requests `apply-and-restart` on its own at start, rather than when the user asks, can therefore
loop while the apply keeps failing. If it does so before it confirms its health, the apply is
refused while its version is pending, every start again counts as an unconfirmed one, and the
fourth rolls that version back (see the health handshake below): confirm first. Because the
applier holds none of the caller's streams, a shell capture
(`x=$(lunepack-runtime apply-and-restart --json)`) returns as soon as the command exits.

The process the applier waits for is named by its pid and start time, so a pid that the system
reuses for another process is never mistaken for it, and it is only ever waited on, never signalled.
By default it is the command's parent process, read when the command starts. `--wait-pid <pid>`
names another one, whose start time is read at once. Either way, a target that is pid 1, gone or a
zombie is the error `process` (19), and nothing is started.

The parent is the app only when the app runs the command itself. A shell runs a lone command in
`x=$(cmd)` directly, so the parent is the shell; but in `x=$(cmd; true)`, or any capture or pipeline
with more than one command, the parent is a subshell that exits at once, and the update would be
applied while the app still runs. So:

- a shell script always passes its own pid: `x=$(lunepack-runtime apply-and-restart --json
  --wait-pid $$)`;
- any caller that runs the command through a wrapper (a shell, `env`, a launcher library) passes
  its own pid with `--wait-pid`.

`--background` (macOS only; accepted everywhere and a no-op elsewhere) makes the applier start the app
without bringing it to the front: the new version, the previous one after a rollback, and the current one
again after a refused apply. It asks LaunchServices to open the bundle without activating it, so the app is
not the applier's child and its exit status is not observable. A new version that crashes before it confirms
its health is therefore noticed at the health deadline (`[update] health_timeout_secs`, `docs/CLI.md`), not
at once, and is then rolled back as an unconfirmed one. The token still travels in the app's environment
only. An app that activates itself in its own code still comes to the front, whatever the option; and when
the bundle's own `Info.plist` cannot be read or names another executable than the entry, the app is started
as a child exactly as without the option (the update completes; only the focus is not protected). Details
in "macOS" below.

## Internal modes

The runtime also has three modes for lunepack's own use: `apply`, `install` and `uninstall` (and, on
Windows, the hidden elevated modes of a per-machine install, below). They
are not part of the app-facing command line and carry no promise to callers: they are **same build
only** (D28). Only the build that started a mode may rely on its arguments, its output or its exit
codes, and a different version's runtime may run them differently. An app does not call them; it
calls `apply-and-restart`, which starts `apply` itself.

| Mode | Started by | What it does |
|---|---|---|
| `apply --wait-pid <pid> --wait-start <ticks> --version <version> [--no-ui] [--background] [-- <args>]` | `apply-and-restart` (detached) | Waits for the process, commits the staged version, flips `current`, starts the new tree's entry with a health token and `<args>`, supervises its health check, rolls back on failure and then collects old trees. An apply that fails after the wait changes nothing and starts the version that exited again (without the token), unless the state moved on (another version current or pending, or the version to apply marked bad): then another applier, such as a second instance's, or a rollback has started the app already. Exit codes 20 to 22 are its own. |
| `install [--silent]` | the first-install flow, from a bootstrap tree | Installs the newest release the tree's own channel offers (M5-D8): the root, feed and channel come only from that tree's update configuration. Exit codes 23, 24, 26 and 27 are its own. |
| `uninstall [--silent]` | the uninstall flow, from a tree of the install | Removes the install this runtime stands in and the desktop integration lunepack made (M5-D10): the install root leaves its path in one rename before it is deleted, so a cut-off uninstall leaves it whole or gone, and the next install or uninstall deletes what is left. Exit codes 24, 25 and 26 are its own. |

On Windows three more modes exist, started only by the same build's unelevated runtime or Setup through the
system's elevation prompt, for a per-machine install: `machine-install --events <id> --for-sid <SID>` (inside
`Setup.exe`), `machine-repair --events <id> --for-sid <SID>` and `machine-uninstall` (phase 1 with the same
two options, phase 2 with `--wait-pid <pid> --wait-start <ticks>` and nothing else). `<id>` is 32 lowercase
hex characters naming the outbound progress pipe the elevated copy creates (`lunepack-setup-<id>`) and
`<SID>` the one account that may read it; neither is a place or a path. An elevated mode reads no environment
variable, makes no temporary directory, looks at no current directory, starts no window and opens no network
connection, and takes the install root from its own image's path (or, for the first install, from the
setup file's own image); nothing in its command line names a location. Their results are exit codes and the
machine record; the progress pipe carries phase lines only ("Per-machine installs" below).

On Linux and macOS the hidden modes of a per-machine install are, again, started only by the same build: Linux
`machine-install --events stdout` (inside the setup file, as root), macOS `machine-install --pkg` (as root, by the
installer package's `postinstall`, and nothing else on its command line), and, on both, `machine-repair --events
stdout`, `machine-uninstall --events stdout` (phase 1) and `machine-uninstall --second [--events stdout]` (phase 2),
and `uninstall --user-copy [--silent]` (the unelevated uninstall's second run, below). `--events stdout` names the
child's own standard output, which `pkexec` leaves in place; a unix elevated mode has no pipe id and no account in its
command line either. It reads no environment variable and no current directory, makes no temporary directory, starts
no window and opens no network connection, and takes the install root from its own image's path (or, for the first
install, from the setup file's own executed image, or from the `.pkg`'s payload folder).

`install` and `uninstall` take one option, `--silent` (no window and no question; on Windows also `/S`),
and, for `uninstall` on Windows, the hand-off options below, and nothing else that names a place: the install root is derived from the runtime's own resolved path and the environment,
never from an argument or the state. Every mode follows the
closed grammar above (a refusal is exit code 2 and one fixed line). `apply` logs schema-1 events to
`logs/runtime.log` under the install root (rotated at 1 MiB to `runtime.log.1`). `install` and
`uninstall` log them to stderr, because the first has no install yet and the second removes the
log's directory, and each ends by printing one final `result` or `error` object on stdout. The
`result`'s `outcome` is `installed`, `uninstalled`, or `uninstalled_with_leftovers` (an
integration item that is not lunepack's was kept and reported).

## Setup files

On Linux and Windows, `lunepack setup` (CLI.md) appends a release's signed payload and a trailer to that
release's runtime (FORMAT.md 14); on Windows the file is `Setup.exe` by name, and the paragraphs on
Windows below add to the rules here. Before it reads its command line, every runtime reads at most the
trailer's 4096 bytes from the end of its own resolved executable. Without the trailer's magic there
it runs as described above, unchanged. With the magic it is a setup file:

- A trailer that does not parse (FORMAT.md 14.2) ends the run with `verify` (7) and one `error`
  object on stdout; it never falls back to another mode.
- The command line is empty or `--silent`; anything else is a usage error (2). (On Linux the line also takes
  `--all-users`, each option once, in any order, and the hidden `machine-install --events stdout`: "Per-machine
  installs (Linux and macOS, M11)" below. On macOS the installer is an app, not a file, and its runtime also takes
  the internal `--ui-stdio`: "macOS" below.)
- The payload is verified under the trailer's root before anything is shown or written: the key
  set, the manifest with no feed (release keys valid now), the whole pack, and the update
  configuration read out of the pack, which must name exactly that root. A failure is `verify`
  (7). A setup file stops installing when its key set expires or its release keys' windows end.
- When a window may be shown (the rules below), `lunepack-ui` is read out of the pack through its
  signed frame into a new private directory (mode 0700) under the app's cache
  (`$XDG_CACHE_HOME/<app id>`, else `~/.cache/<app id>`) and started from there; the directory is
  removed when the run ends. A directory an earlier run left there is removed only when its marker
  names this app and a process that no longer runs. A release packed without `--ui`, or a UI that
  cannot be written out, means a run without a window.
- The welcome question shows the name, version, publisher, install location and size from the
  verified manifest and configuration. Then the release is installed into
  `<data home>/<app id>` from the payload's own frames, exactly as `install` commits it (its exit
  codes, `already_installed` (23) for an existing install, and its desktop integration), with
  progress phases `install` and `stage`. The done question's launch answer starts the installed
  entry.
- Events go to stderr and the run ends with one `result` or `error` object on stdout, `command`
  `setup`.
- Windows: the command line is empty, `--silent` or `/S` (the same thing). `R` is found after the payload
  is verified and before anything is written, by the rule of `docs/FORMAT.md` 16: the folder of an existing
  install of the app id, whatever its name, else a folder named after the display name. A refusal there
  (a taken name, a name the Windows rule refuses, copies of the install, too many entries) is exit 26
  `install_mismatch` or 14 `update_config` with nothing written under the programs folder. The window's
  program is written to a new private directory directly under the temp directory,
  `lunepack-setup-ui-<16 hex>`, with a marker, and removed when the run ends; a window is never started
  under `/S`. A setup file that was signed with Authenticode after it was built is found by the rule of
  `docs/FORMAT.md` 14.3; a byte added after its signature makes it exit 7 `verify`.
- A rerun on an installed app (the same app id found by its record) installs nothing: it applies the
  integration of the installed version again under the lock (the launcher stub at `R`, the shortcut, the
  uninstall entry and the declarations), then exits 23 `already_installed`. A stub lost between the two
  renames of a self-replace, or an entry the user deleted, is restored this way. An entry that is not
  lunepack's is left alone, and the exit code stays 23; any other failure of the repair is that error. The
  rerun never changes which version is installed, whatever version the Setup file carries.
- Linux, for all users: the command line also takes `--all-users`; a setup file run as root installs for all users
  and never per user, and takes no anchor (its payload is copied out of its own executed image and verified under
  its trailer's root, "Per-machine installs (Linux and macOS, M11)" below).
- Windows, for all users: the command line also takes `--all-users` ("Per-machine installs" below). A Windows
  setup file carries the anchor of `docs/FORMAT.md` 14.5 and checks its payload against it before anything is
  shown or written.

## Windows

The Windows runtime is `lunepack-runtime.exe`, built for the Windows subsystem (M7-D6): it never opens a
console window, whatever process flags the app that starts it uses, and piped standard handles (the
documented use, `check --json` read by the app) work because the parent passes them. Typed in `cmd` it
returns at once and prints nothing visible unless its output is redirected; use `start /wait` or a pipe.

**The launcher stub.** The app's shortcuts, its uninstall entry and its declared file types and URL schemes
start the stub at `R`, not the runtime. Its exit codes and its one reserved argument are part of the
launch contract (`docs/FORMAT.md` 15): 90 not installed, 91 install state unreadable, 92 configuration
unreadable, 93 the executable is missing, 94 a link where a file or folder belongs, 95 the app could not be
started; `--lunepack-uninstall` (optionally with `/S`) runs the uninstall of the current version. An app that
needs to know whether it was started by the stub need not: the stub passes its command line, environment and
working directory through unchanged. For the same reason an app that declares `url_schemes` must treat only
the first argument of such a launch as the URL, and only when it starts with one of its own schemes and `:`.
The registered command is `"<stub>" "%1"`, and a launcher that does not escape `"` in a URL can split it
into several arguments (`docs/FORMAT.md` 13.4): the app ignores or refuses the rest and never reads them as
flags.

**Uninstall.** A running executable cannot be deleted, so `uninstall`, started from inside `R`, is the first
of two phases. Phase 1 derives `R` from its own path and checks it as `docs/FORMAT.md` 16 says, copies its own
executable (and `lunepack-ui.exe` when that is a regular file beside it) into a new directory under the temp
directory, `lunepack-uninstall-<16 hex>`, with a marker naming the app and the process, starts the copy
detached as phase 2 and exits 0 without deleting anything. Phase 2 (`uninstall --install-root <R>
--wait-pid <pid> --wait-start <ticks>`, same build only, accepted only when started from such a directory)
waits up to 10 seconds for phase 1, checks the root it was given again (a real directory, not a reparse
point, whose parent is the programs folder and which holds a record of the marker's app; the folder's name is
not checked) and runs the uninstall of the Internal modes table. The copy stays in the temp directory until
a later run of any lunepack app removes it (a directory named exactly `lunepack-(uninstall|setup-ui)-<16 hex>`
whose marker names a process that no longer runs) or Windows' temp cleanup does; the install folder, the
shortcut, the registry entries and the declarations are gone.

On Windows the uninstall releases the install lock right before it renames `R` to its tombstone
(M7-D21): every lunepack process that holds the lock keeps a file under `R` open, so the rename can succeed
only while none does. A failed rename reports the error and deletes nothing.

**Outcome notice.** An interactive install, setup or uninstall that ends with no window that showed its
outcome (no `lunepack-ui.exe`, one that failed to start or was lost) shows one native message box, because the
process has no console to say it on. A setup that fails before it has verified the app's name (a refused
payload) shows the same box titled `Setup`, with the closed result code only; one refused after that (its
install folder taken, an install it cannot read or tell apart) names the app. A setup run with arguments it
does not accept shows no box, even when its file is malformed: arguments mean a command-line caller. A setup rerun over
the installed app (exit 23) says the app is already installed, as a normal end, not a failure. It appears only after the outcome is committed and never under
`/S` or `--silent`, `--no-ui`, `LUNEPACK_NO_UI`, nor for a cancellation the user chose.

**The application user model id.** The Start-menu shortcut carries the app id as its application user model
id, so the taskbar groups the app's windows under it. The Rust facade's `startup()` sets it for the process
(`SetCurrentProcessExplicitAppUserModelID`) before the app creates a window. An app in another language
sets the same id itself, once, before it shows a window; its value is the app id of `lunepack.toml`.

**Transient locks.** A rename or removal that fails because an antivirus scanner or an indexer briefly holds
a file (access denied, sharing violation or lock violation) is retried for at most about two seconds in
total; the last error is reported unchanged.

**Renaming the install folder** is not supported (`docs/FORMAT.md` 16): the app still starts from the stub in
the renamed folder, but its Start-menu shortcut no longer points at the install, and updates report the
shortcut as a conflict until the app is reinstalled.

## Per-machine installs (Windows, M10)

An app packed with the update service (`pack --service`, CLI.md) can be installed **for all users**: its tree
lives under `Program Files` (`docs/FORMAT.md` 18), where a standard user cannot write, and a small
LocalSystem service updates it, health-checks it, rolls it back and removes old versions with no prompt per
update (`docs/FORMAT.md` 19; D12, M10-D1). A release packed without `--service` installs per user only and
its installer offers no choice.

**Scope is by location** (M10-D14). An install is per machine when the running executable is inside
`<Program Files>\<name>\app\<version>\` and the newest record under that `<name>\.lunepack\state` is of
scope `machine` and names the app. Never an argument, an environment variable or a registry value. One
install is visible at a time: Setup refuses (`already_installed`, 23) to install for all users while the
installing user has a per-user install of the app, and per user while a per-machine install exists.

**Choosing it.** The window's welcome screen offers a tick box, "Install for all users", when the release
carries the service and the process does not hold an administrator's full token. The same Setup file serves
both; the window never runs elevated (M10-D15). What a run does is decided from who runs it and what it was
asked:

| Who runs `Setup.exe` | Without `--all-users` | With `--all-users` |
|---|---|---|
| a standard user, or an administrator in an ordinary window with UAC on (a filtered token) | the window, per user, with the tick box | `--silent`: exit 30 `elevation_required`, no prompt, nothing written; with a window: the choice is taken, and proceeding shows the system's prompt (a credential prompt for a standard user, a consent prompt for an administrator) |
| an administrator with no split token (UAC off, the built-in Administrator account) | the window, per user, with the tick box | installs for all users in this process, with no window (`--silent` or not) |
| a process holding the full token of an elevation ("Run as administrator") | one fixed message box titled `Setup` ("This installer does not run with administrator rights. Start it normally and choose "Install for all users", or start it with --all-users from an administrator prompt."), then exit 2 | installs for all users in this process, headless |

A release without the service asked to install for all users is exit 34 `per_machine_unavailable`. When the
tick box is used the unelevated Setup starts a copy of itself elevated (`machine-install`; also when the user
is an administrator with no split token, so the hand-off is the same everywhere), the system asks once when
it needs to, and the copy writes its
progress into an outbound pipe the window reads; the install's result is the copy's exit code and the
machine record, never what came through the pipe. Declining is exit 31 `elevation_declined` with nothing
changed (the window shows a retry screen); a window lost after the hand-off began does not stop the install
(a warning, one notice, exit 0). The elevated side copies the payload out of its own image into an
administrator-only folder under Program Files and verifies it there against the anchor of the image the
administrator approved (`docs/FORMAT.md` 14.5) before it creates anything; a directory it created that is not
protected as FORMAT 18.2 says stops the install (exit 35 `not_protected`).

The check for "the installing user has a per-user install of this app" is made only by an **unelevated**
process, before it elevates or installs. A process holding the full token, and every elevated mode, opens
nothing under any user's profile; for them only the engine's own check of the machine side applies, which
is authoritative for a per-machine install. So an administrator who runs `Setup.exe --all-users` from an
elevated prompt while holding a per-user install of the same app ends with both installs: the per-user one
is not touched, and its own uninstall removes it.

**Updating.** `check` and `download` run as the user, with the user's own cache and lock. `download` also
stages: the library uploads exactly the documents it verified and the objects its cache holds to the service
(over the pipe, never a path), which verifies them again in its own storage and builds the tree. `apply-and-restart`
starts the applier as for a user install; the applier asks the service to `apply` the staged version, which
returns a health token, starts the new version with the token in its environment (never on a command line,
in a log or in an event) and supervises it by reading the machine record; a crash or the health timeout
calls `rollback`, a `not_pending` or `token_mismatch` answer means someone else resolved it and the applier
reports what the record says, and it relaunches the launcher stub. `startup` and `confirm` use `attempt` and
`confirm`: a start of a pending version that has no token asks `attempt`, so a supervisor that died is
replaced by the first starts of any user (three failed leases roll the version back). The runtime and the
library write nothing under `R`, to the machine record or to HKLM: every such change is a request to the
service. **None of the five commands ever asks for elevation or shows a prompt** (C4); only `repair` and
`uninstall` may, and with `--silent` they exit 30 instead.

**When the service cannot be used** the command exits 32 `service_unavailable` with a closed `reason`
(`not_installed`, `disabled`, `start_failed`, `untrusted`, `timeout`, `protocol`, `unsupported`) and the app
keeps running its current version. When an administrator disabled the service (start type Disabled, or
deleted by hand) standard users get no updates: the reason is `disabled` (or `not_installed`), and updates
resume when an administrator runs `repair` or re-enables the service. This is treated like the policy
switch below: an administrator's deliberate choice, not something a standard user routes around
(M10-D13). An administrator's policy `DisableSelfUpdate` (`docs/FORMAT.md` 18.4) makes `check`, `download`
and `apply-and-restart` exit 33 `disabled_by_policy` before any request or download; `NoUpdateUi` makes the
runtime show no update window, exactly as `LUNEPACK_NO_UI` does.

**`repair`** (a per-machine install only, else exit 2) re-creates the service's registration, its descriptor and
its demand start from the confirmed current version, after one administrator approval: an administrator's
process runs it in-process; a standard user's starts `lunepack-runtime.exe machine-repair` from
`<name>\app\<current>\` through the elevation prompt. There is no per-update elevated apply: with one
protocol version a broken new service binary is kept out by the self-test before the registration switches,
and a damaged registration is what `repair` is for.

**Uninstall.** Started as for a user install (the stub with `--lunepack-uninstall`, Settings' Uninstall entry,
`lunepack-runtime uninstall`). The unelevated runtime asks in the window (or `--silent` is exit 30), then starts
the runtime inside `<name>\app\<current>\` elevated as `machine-uninstall`. That image is always the one under
Program Files; the install root is derived from its own path and checked against the machine record, and no
other path is accepted. Phase 1 copies it into a new administrator-only folder `.lunepack-uninstall-<32 hex>`
directly under Program Files and starts the copy; phase 2 reads the install to remove from a marker in its own
folder, checks it again, and runs the engine's uninstall in this order: the service is removed, the lock
released, the whole tree checked for use, the integration removed, the root renamed away, the renamed tree
checked once more, then deleted. A refusal at any step puts back what came before and exits 25 `in_use` (or 24
`integration`): a refused uninstall leaves the install as it was. The copy's folder is registered for deletion
at the next restart. The uninstalling user's per-user home is removed; other users' homes are left.
A process that already holds an administrator's token (run as administrator, or UAC off) never makes the
temporary copy, which its own unelevated processes could replace, and shows no window: the runtime inside
`<name>\app\<current>\` runs phase 1 itself, headless, and exits 0 once phase 2 is started; phase 2 waits for it
to end, then runs as above (after waiting up to 30 seconds for a progress reader that does not come), and its
exit code is the result. That administrator's own per-user home is left.

**Events.** A per-machine install queues none; each user's `first_run` and `updated` events come from that user's
own counters (`docs/FORMAT.md` 12.9). `installed` is not delivered.

**Exit codes of this section.** 30 and 31 and 34 and 35 belong to Setup, 32 and 33 to the commands above; 17
stays for operations a per-machine install does not support (adoption on macOS, and `install` run from inside
a machine tree), and the table above lists all of them. Schema 1 does not change: the new `kind`s are
additive.

## Per-machine installs (Linux and macOS, M11)

An app packed with the update service (`pack --service`, CLI.md) can be installed **for all users** on Linux and
macOS as well: its tree lives where a standard user cannot write (`docs/FORMAT.md` 20: `/opt/<app id>` on Linux; on
macOS the bundle in `/Applications` and the state under `/Library/Application Support/lunepack/<app id>`), and a
root daemon that any local user's copy of the app starts through a unix socket updates it, health-checks it,
rolls it back and removes old versions with no prompt per update (D12, M11-D1 to M11-D16). The protocol is the
Windows one, version 1, unchanged (`docs/FORMAT.md` 19.8). A release packed without `--service` installs per user
only and its installer offers no choice. Everything in "Per-machine installs (Windows, M10)" about scope by
location, updating, the policy, events and exit codes 32 and 33 holds here, with the differences below.

**Scope is by location** (M10-D14, M11-D6). An install is per machine when the running executable is in
`<machine home>/<app id>/app/<version>/` (Linux), or is the live bundle `R/bundle` names or the old copy a swap
parks in `R/app/<version>/` (macOS), and the newest record under `R/.lunepack/state` is of scope `machine` and
names the app. Never an argument, an environment variable, a unit or a property list. One install is visible at a
time: the setup refuses (`already_installed`, 23) to install for all users while the installing user has a per-user
install of the app, and per user while a per-machine install exists. (A root process cannot see other users'
per-user installs: an administrator who installs for all users while another user keeps a per-user install ends with
both; the per-user one is not touched.)

### Linux: the first install

The same setup file serves both. The welcome screen offers the tick box "Install for all users" when the release
carries the service and the process is not root. What a run does is decided from who runs it and what it was asked:

| Who runs the setup file | Without `--all-users` | With `--all-users` |
|---|---|---|
| a user other than root (an administrator included) | the window, per user, with the tick box | `--silent`: exit 30 `elevation_required`, no prompt, nothing written; with a window: the choice is taken, and proceeding starts `pkexec` |
| root (a root shell, `sudo`) | one fixed line on stderr and exit 2, no window, nothing written | installs for all users in this process, headless (no window runs as root, D35) |

A release without the service asked to install for all users is exit 34. When the choice is made, the unelevated
setup runs `/usr/bin/pkexec <the setup file, canonical absolute path> machine-install --events stdout`, with
standard input on `/dev/null` and a pipe on standard output (M11-D9). `pkexec` asks the system's authentication
agent once, runs the file as root with its own clean environment, keeps the pipe, closes every descriptor above 2
and passes the exit code through. The root copy writes its progress as the same relay lines the Windows pipe
carries, which the unelevated side relays to the window; the install's result is the copy's exit code and the
machine record, never a line that came through the pipe. Exit 126 is the user declining (31
`elevation_declined`, a retry screen); exit 127, or no `/usr/bin/pkexec` at all, means nothing can ask: the window
shows the screen "Finish in a terminal" with the command

```
sudo '<the setup file, canonical absolute path>' --all-users
```

(single-quoted, each `'` in the path written `'\''`; the window shows it verbatim, offers "Copy command" and never
runs it; a path that is not text or whose command exceeds the screen's 1024 bytes shows no command) and the run
ends with exit 30. The root side copies the payload out of **its own executed image** (it opens `/proc/self/exe`
once, at the start) into a new admin-only folder `.lunepack-install-<32 hex>` in `/opt`, verifies the copy under
the trailer's root (the signed key set, the manifest and the pack) before it creates anything, and takes nothing
from its caller: no environment variable, no current directory, no path. There is no anchor as on Windows: the
`pkexec` prompt names a path, not a publisher, so a digest bound to the image would not tell the administrator a
genuine file from a swapped one (`docs/THREAT-MODEL.md`).

### macOS: the first install

A `macos-*` release with the service has, besides the `.dmg`, the all-users `.pkg` (CLI.md, `setup`), and the
installer app carries the same file. The window's tick box "Install for all users" is offered when it does; on
proceeding the runtime opens the package with `/usr/bin/open` (never with privileges of its own, M11-D8), the
window says "Continue in Installer", and the run ends with exit 0 and the `result` outcome `handed_off` (nothing
is installed by that process; it first refuses `already_installed` for a per-user install of this user or an
existing machine record). A person can also open the `.pkg` from the `.dmg` or from the release directory. Installer
asks for the administrator's password, places the runtime and the payload file below
`/Library/Application Support/lunepack/.installer/<app id>/` (root-only) and runs the package's one `postinstall`
line as root: `lunepack-runtime machine-install --pkg`. That mode takes no other argument and reads no environment
variable (Installer's `$1` to `$4` are never read). Before it reads anything it requires that it runs as root, that
its own resolved path is exactly `<machine home>/.installer/<app id>/lunepack-runtime` (compared with what the
kernel names it), that the machine home is a machine tree and searchable, and that `.installer` and the app's
folder are admin-only; the payload file must be a regular file owned by root that neither group nor others may
write. It copies the payload into `.lunepack-install-<32 hex>`, verifies the copy under the trailer's root, and then
installs through the engine: the record, the trees, the bundle at `/Applications/<name>.app` (the second name
`<name> (<app id>).app` when the first is taken; an existing entry is never touched), the LaunchDaemon and the
integration. A rerun of the package over the installed version repairs it (the engine's `repair`, exit 0); over
another version it is `already_installed`. The result is the exit code of the script. The system may list the
daemon under System Settings > General > Login Items & Extensions and show a notice for a background item; what it
shows is what the person check (`scripts/macos-machine-user-check.sh`) records, and an administrator who switches
such an entry off would stop updates for standard users as a disabled service does on Windows (not yet observed on a
real Mac; `docs/THREAT-MODEL.md`).

### Updating, repair, the policy

`check`, `download`, `startup` and `confirm` run as the user with the user's own cache and lock, `download` stages
through the socket, `apply-and-restart` starts the applier as for a user install, and the applier asks the service
to `apply`: the service, as root, makes the staged version current and projects it (Linux: the link `R/current`;
macOS: the swap of the live bundle `B`, which waits for the app's own exit as the applier does), and returns the
health token; the applier starts the new version from `R/current/<entry>` (Linux) or `B`'s entry (macOS) with the
token in its environment, supervises it and calls `rollback` on a crash or at the health timeout (`docs/FORMAT.md`
19.5). **None of the five commands ever asks for elevation or shows a prompt**; only `repair`, `uninstall` and the
first install may. The service's removal guard asks the all-users in-use scan before and after each rename that
takes a path away from new launches, and any process it cannot read counts as in use (M11-D13), so a tree another
user runs is never deleted. `service_unavailable` carries the closed reasons of the table above: `not_installed`
when the socket is not there (after three seconds), `disabled` when nobody listens, `untrusted` when the socket's
owner, folder or peer is not root (`docs/FORMAT.md` 20.3). A second client that connects while the service
serves another connection waits in the socket's queue, and a hello that does not come in ten seconds is exit 4
`busy` on Linux and macOS, as on Windows (M11-D15; a daemon that hangs reads as busy too); `timeout` is a later
answer that does not come. The administrator's policy file (`docs/FORMAT.md` 20.6) makes `check`, `download` and
`apply-and-restart` exit 33 before any request or download, and `NoUpdateUi` makes the runtime show no update
window, as on Windows.

**`repair`** (a per-machine install only, else exit 2) re-creates the registration (Linux: the two units and the
stable link; macOS: the LaunchDaemon and the link) from the confirmed current version after one administrator
approval. As root it runs in process. As a standard user on Linux it asks `pkexec` to run
`<R>/app/<current>/lunepack-runtime machine-repair --events stdout`, the root-owned image inside `R`, never a copy
the user can change; with `--silent`, or without `pkexec`, it exits 30. On macOS there is no prompt of our own: it
exits 30, and an administrator runs `sudo '<runtime path>' repair`; running the `.pkg` of the installed version
again repairs too.

### Uninstall

Started as for a user install (`lunepack-runtime uninstall`). The unelevated runtime asks in the window to confirm,
or `--silent` is exit 30.

- Linux: it first copies itself (and `lunepack-ui` when that is a regular file beside it) into a new private
  folder `lunepack-uninstall-<16 hex>` of the user's per-user home of the install (`docs/FORMAT.md` 20.7), with a
  marker naming the app and the process, and becomes the copy (`uninstall --user-copy`), because a process of the
  user running from `R` would make the removal guard refuse (`in_use`, 25). The copy asks `pkexec` to run `<R>/app/<current>/lunepack-runtime machine-uninstall
  --events stdout`; no other path is accepted. Declined is 31; without `pkexec` the window shows the command
  `sudo '<runtime path>' uninstall` and the run ends with 30.
- macOS: no prompt of our own; the window shows the same command and the run ends with 30, nothing changed.
- As root (`sudo '<runtime path>' uninstall`, or the elevated copy above) phase 1 derives the install from its own
  path (on macOS from its path inside `B`) and checks it against the machine record before anything is copied,
  copies the runtime into a new admin-only folder `.lunepack-uninstall-<16 hex>` directly in the machine home with a
  marker, and `exec`s the copy as phase 2 (`machine-uninstall --second`), so the pipe and the process stay the same
  and the copy's exit code is the result. Phase 2 re-validates and runs the engine's uninstall in this order: the
  registration is removed (the units and the socket file, or the LaunchDaemon), the lock released, the whole tree
  checked for use, the integration removed, `R` renamed to its tombstone (on macOS `B` first renamed to its
  own, after `R`'s scan), the renamed tree checked once more, then deleted, and finally the copy's own folder. A
  refusal at any step puts back what came before and exits 25 `in_use` (or 24 `integration`): a refused
  uninstall leaves the install as it was. The uninstalling user's per-user home is removed; other users' homes are
  left.

**Events and exit codes.** A per-machine install queues none; each user's `first_run` and `updated` come from that
user's own counters (`docs/FORMAT.md` 12.9). 30, 31, 34 and 35 belong to the first install and to `repair` and
`uninstall`, 32 and 33 to the commands above, and 17 stays for what a per-machine install does not support
(adoption on macOS, `install` run from inside a machine tree). Schema 1 does not change: no new `kind` was added,
and the macOS installer's `result` has one new `outcome`, `handed_off`.

## macOS

The macOS runtime is `lunepack-runtime` in `Contents/MacOS` beside the entry. An app that is installed per
user lives in a bundle `B` in `~/Applications` that the install records (`docs/FORMAT.md` 17); everything
here is per user (M8-D2), except for the per-machine install ("Per-machine installs (Linux and macOS, M11)" above).

**Which copy is the install.** The runtime decides from its own resolved path, before it reads any state
or the network, and in this order:

1. A runtime inside a translocated app (a `nullfs` mount, or a path with an `AppTranslocation` component) or
   on a read-only volume (a mounted disk image) is exit 28 `unsupported_location` with `reason`
   `translocated` or `read_only`, in every mode (`check` included, so a translocated app is told to move
   instead of being told it is not installed). Nothing is read, written or fetched. Move the app to the
   Applications folder of the user and open it from there. Gatekeeper translocates a quarantined app that
   was started from where it was downloaded. Whether that happens to an app is the system's decision and
   depends on its signature and notarization; translocation has not been exercised on a real quarantined
   app (it needs a notarized one, M9), so this refusal is proven only with the mount and path as the
   system names them.
2. A tree that is `R/versions/<its own version>` is an old instance of the install (a process the
   previous version started before an update keeps running from the path the update gave its tree). It
   is the install's.
3. A bundle that `R/bundle` names is the install's. A second copy of an installed app is a development run
   (`check` and `download` answer 3 `not_installed`, `startup` goes on with no events): one install per app
   id per user.
4. A bundle the user moved within its volume (Finder moved it; the old pointer's target is gone, and the
   bundle has the device and inode `R/bundle.id` records and the record's current version) is followed: the
   next start re-points `R/bundle` and refreshes the integration, under the install lock. A copy, a bundle
   extracted again, a bundle moved to another volume or one in the Trash is never followed.
5. A bundle directly in `~/Applications` or `/Applications` whose install is gone or never was (the
   adoption cases below) is adoptable.
6. Anything else, such as a build folder, `~/Downloads` or the Desktop, is a development run: exit 3, no
   network, nothing written.

Before a mode moves or removes anything of an install (the applier, startup's repair of a swap, uninstall,
the installer), the place of `B` is checked: its folder and `R/versions` on one volume (else `other_volume`),
`B` owned by the user (else `not_owned`; a root-owned `B` that is not the live bundle of a per-machine install
of this app is `machine_scope`, exit 17; the live bundle of one is a machine install, by location) and the user able to create entries in `B`'s folder (else `not_writable`; the folder need not be the
user's own, so an administrator's app in `/Applications` keeps updating). It is exit 28 with that `reason`,
nothing committed and, in the applier, the app started again.

**Adoption** (`check`, and so `download`). A copy that is adoptable is adopted by the update check, and
nowhere else: not by `startup`, which makes no request, and not by `confirm` or `apply-and-restart`. This is
how a bundle dragged out of a `.zip`, or a copy the user put back after trashing the app, or one that
replaced the live bundle at its own path (Finder's Replace), becomes an install:

- **The place rule.** Only a bundle directly in `~/Applications` or `/Applications` is adopted, and only when
  `R` holds no record, a record with no current version, or an orphaned or replaced one (`docs/FORMAT.md`
  17.4); a bundle in a build folder, `~/Downloads`, the Desktop, a subfolder or the Trash never causes a
  request. A live install makes any other copy `not_installed`.
- **Network only there.** The check already uses the network. It verifies the root, key set and feed from
  the bundle's own configuration, as `install` does from its bootstrap tree, takes the release that is
  exactly the bundle's version for its target (none is 27 `no_release`), verifies its manifest, and then proves
  the bundle equal to it: the same paths, sizes, SHA-256 hashes, executable bits and link targets, no extra
  entry. Any difference is 7 `verify`; a transport failure is 8; `busy` is 4; a place that cannot be updated
  is 28. Nothing is executed and no extended attribute is changed.
- **The result.** The progress phase `adopt` covers the hashing (the check holds the install lock meanwhile,
  as it does across the network, so a concurrent call is `busy`, and a large app's first check takes
  longer). On success the check carries `"adopted": true` in that run only, the events `installed` and
  `first_run` are queued and delivered by the app's next `startup`, and the same check reports the update.
  A failure leaves the bundle untouched and the app runs as a development run; the next check tries
  again. What may remain is a record without a current version and floors raised from verified documents
  only (as after a cut-off `install`).
- **A replaced bundle.** Until its first check adopts it, a bundle that replaced the live one at its own
  path is a development run: `startup` succeeds and `installed()` says none, `uninstall` from it is 3, and an
  installer run over it still answers 23 (the recovery for a copy that does not verify is to move it to
  the Trash and run the installer, which treats the install as orphaned). An adoption that replaces an
  orphaned or replaced install keeps its anti-rollback floors and gets a new install id.
- **A cut after the identity write.** An adoption of a same-version orphan that is cut off after its
  identity was written leaves a disk that a Finder move leaves too; the next start follows it as a move. The
  install keeps its record and loses only the new install id and the two events. This is accepted.

**An update** is the record first, then a swap: the new tree is staged in `R/versions/<new>`, the record
commits it, and the applier makes `B` hold it with `renamex_np(RENAME_SWAP)`, or, on a volume that does not
support it, the journaled two-rename (`docs/FORMAT.md` 17.3). The previous bundle is kept as
`R/versions/<previous>` for the rollback and removed only by garbage collection after a confirmation. The new
version is started from `B`'s own entry with the token in its environment (never on a command line),
`--background` as described above, and the rest is the health handshake as on Linux. A crash at any point is
healed by the next start or apply. Without `--background` the relaunch is a direct start of the entry, as
on Linux and Windows, so the new app is the applier's child and a crash before it confirms is seen at once.

**The update window** is a helper app nested in the bundle,
`Contents/Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui`, found from the runtime's own path
(`pack --ui`, `docs/CLI.md`); without it the runtime looks for `lunepack-ui` beside itself, the installer
app's layout, and without that runs headless. Nothing else about the window changes.

**The installer.** A `macos-*` release is installed from `Install <name>.app` in the `.dmg` that
`lunepack setup` writes (`docs/FORMAT.md` 14.4). Its main executable is the release's `lunepack-ui`, which
starts the runtime beside it with the internal `--ui-stdio`: the UI is the runtime's parent, and the frames of
the channel go over the runtime's own standard input and output, which then carry nothing else (the
result and events go to standard error). The runtime never signals its parent, treats every message of
it as untrusted as any UI's, and carries on headless when it is lost. Without a UI, or with `--silent`, the
runtime installs from its payload with no window. The payload is verified first (exit 7), then the install
goes into `~/Applications/<name>.app` and `R` (exit codes of `install`; 23 for an existing install, whose
integration it repairs). Only the place of the new bundle is judged, never the installer's own: an installer
on a read-only image or translocated installs. No uninstaller is in the image: uninstall is
`lunepack-runtime uninstall [--silent]` from the installed bundle. `--ui-stdio` is same build only (D28) and
carries no promise to callers.

**Uninstall** (`uninstall [--silent]`, M8-D15) takes `B` from its own path and requires it to be what
`R/bundle` names and its place to pass the checks above (28 otherwise; 26 for a bundle that is not the install's, and
for a moved bundle not yet followed: start the app once, and it follows). It refuses (25) while any process
of the user runs from `B` or from a tree in `R`, then removes, under the lock, `B` (renamed to
`.<app id>.removing-<16 hex>` in its folder, then deleted), `R` (M5-D10's tombstone, then deleted) and the
LaunchAgent entry if it is the app's, in that order. A foreign file beside `B`, another app's LaunchAgent and
another entry of the apps folder are never touched. An entry that is not lunepack's is left and reported
(`uninstalled_with_leftovers`). The interactive uninstall may offer to open the folder of a leftover
(`/usr/bin/open`, the same rule as `xdg-open`). A tombstone of `B` that a cut-off uninstall left in the apps
folder is removed by the next uninstall, install, installer run or adoption (a real directory named exactly
`.<app id>.removing-<16 hex>`; nothing else there).

**Declarations.** `autostart = true` writes `~/Library/LaunchAgents/<app id>.lunepack.plist` (`Label` the
same, `ProgramArguments` the entry inside `B`, `RunAtLoad`, `LimitLoadToSessionType` `Aqua`). It is never
loaded with `launchctl`, so it takes effect at the next sign-in; it is replaced or removed only when its
`Label` is ours. `file_types` and `url_schemes` are not applied: macOS reads them from the app's own
`Info.plist`.

**Outcome notice.** An interactive install, setup or uninstall that ends with no window that showed its
outcome shows one native alert, as on Windows, through `/usr/bin/osascript` running one fixed script that
reads the title, the text and the kind from its arguments (no string is ever put into script source). The
text is fixed (the app's name, the result and the closed result code), the alert dismisses itself after 120
seconds and the process is killed shortly after, except that an exit 28 says "Move <name> to your Applications
folder and open it from there." (M8-D4), and it is shown only when the run is provably interactive
and never under `--silent`, `--no-ui`, `LUNEPACK_NO_UI`, for a cancellation the user chose, or after a window
showed the outcome.

**In use (exit 25).** The scan reads, for every process of the user, its executable, working directory and open
files, and compares them with the tree as the kernel names it (so a swap that moved a running app's tree is
seen under its new path). Files that a process only maps (a library loaded from the tree) are not read. A
process of the user that cannot be read counts as in use, with two exceptions: a system daemon that the
kernel refuses to show beyond its executable is judged by what is readable, and a process whose executable
file was deleted is judged by its working
directory and open files alone, counting as in use only if one of them lies in the tree, or if the kernel
refuses its working directory too (M5-D9 amended by M8-D19). A read that fails on a process that is starting
or ending is repeated up to three more times, ten milliseconds apart, and a process that has meanwhile ended
is not in use. `docs/THREAT-MODEL.md` lists what that does not see.

**Extended attributes.** lunepack neither sets nor removes `com.apple.quarantine` and copies none into a new
tree (`docs/FORMAT.md` 17.3).

## The window

`install`, `uninstall`, `apply` and a setup file show their progress and ask their questions in a
window when they can: they start `lunepack-ui` from the directory of the runtime's own resolved path
(a setup file: from its private directory, above) (never through
`PATH`, `current` or a link), with the fixed argument `--engine`, its standard input and output as
the channel and its error stream on `/dev/null`, and without `LUNEPACK_HEALTH_TOKEN` in its
environment. The window only shows and asks; every answer is checked by the runtime, and a window
that fails changes no outcome and no exit code. No window is started under `--silent` (`install`, a setup file,
`uninstall`) or `--no-ui` (`apply`, `apply-and-restart`), when `LUNEPACK_NO_UI` is set to anything
but empty or `0`, on Linux when neither `DISPLAY` nor `WAYLAND_DISPLAY` is set, or when
`lunepack-ui` is missing; the mode then runs headless and every question takes its default
(proceed; the app is not launched). The app-facing commands never start one. On macOS there is no display
test (a window server is assumed), the update window is the helper app's `lunepack-ui` (below), and the
installer's window is the installer app's own main executable, which starts the runtime (`--ui-stdio`).

`install` asks before it installs, and `uninstall` before it removes: cancelling there, or the window
being lost there (it exits, crashes, stops answering or breaks the protocol), ends the mode with
`cancelled` (5) and nothing changed. A window lost while the operation runs is closed, and the
operation goes on headless. After the outcome, the window's answer only decides whether `install`
tries again after a failure or starts the app, and whether `uninstall` opens a folder it lists;
`apply` relaunches and decides before the window hears of the outcome. A window that stops reading,
does not answer a liveness probe at a question within 15 seconds or does not exit within 5 seconds
of being closed is killed, so the mode always ends. A stopped window is logged once as a `warning` with `code` `ui_stopped`, a `reason`
from `stalled`, `hung`, `exited`, `protocol`, `build_mismatch`, `hello_timeout` and `spawn_failed`,
and the window's own exit code as `ui_exit_code` when it exited with one.

The window and the runtime are one build (D28): the window says hello first with its build id and the
runtime refuses another. The window's own exit codes are typed, and the runtime reads them only to
name the reason; they carry no promise outside that build.

| Window exit code | Meaning | `ui_stopped` reason |
|---|---|---|
| 0 | closed after the runtime's `Close` | none (the normal end) |
| 2 | usage (anything but `--engine`) | `exited` |
| 10 | no display, or the window system could not start | `exited` |
| 11 | no graphics adapter (a hardware one, then a software one, D36) | `exited` |
| 12 | the runtime sent a frame the protocol or the flow does not allow | `protocol` |
| 13 | the runtime's end of the channel closed before `Close` | `exited` |
| 14 | the runtime's build id is not the window's | `build_mismatch` |

The reasons not tied to a code are `stalled` (a frame that did not fit the bounded queue, or one write
in progress for more than 2 seconds), `hung` (no answer to a liveness probe within 15 seconds),
`hello_timeout` (no hello within 20 seconds of the start; the wait never holds the operation up),
`protocol` (also for a frame, a choice or an answer the runtime refuses) and `spawn_failed` (the
window could not be started). A window that was never wanted or never found (the rules above) logs
nothing. With every reason the mode goes on headless: a question open at that moment takes the
default the loss implies, which is `cancelled` (5) before any change and the headless default after
it (M6-D5).

The uninstall's `Show folder` asks the runtime to open the folder of one leftover it listed. The
runtime checks the index against that list and starts the desktop's opener on the folder
(`xdg-open <folder>`, without a shell, found among the absolute entries of `PATH`), at most once a second; it changes nothing.
The window opens nothing itself.

## Cancel

End the child process (SIGTERM). A download keeps its partial file and resumes on the next run.
A runtime whose stdout is closed or no longer read cancels itself the same way and exits 5, so a
caller that stops reading cancels the download too. A reader that never reads cannot stall it: the
output is written by its own thread, and a final line a stuck reader does not take is dropped after
two seconds.

## The health handshake (D43)

A new version is started by the applier with a health token in its environment
(`LUNEPACK_HEALTH_TOKEN`), and it is rolled back unless it confirms that it works. An app that
drives only this command line therefore runs, in order:

1. `startup -- <its own arguments>` first thing in `main`, and acts on the result: `events` are the
   things that happened since its last start (`installed`, `updated`, `first_run`; each is delivered
   once), and `action: "exit"` means this version was rolled back and the previous one has been
   started in its place, so the app must exit at once;
2. `confirm` once it is working. The child inherits the token, so the app passes nothing. With no
   pending launch, `confirm` succeeds and does nothing, so an app may run it on every start.

An app that never runs `confirm` has every update rolled back: an unsupervised start of a pending
version counts an attempt, and the fourth rolls back; a supervised one is rolled back when it exits
badly or does not confirm within the health timeout (`[update] health_timeout_secs`, `docs/CLI.md`).
This is the one meaning of "healthy" for every app, Rust or not.

An app that captures output in a shell must run the command directly (`x=$(lunepack-runtime check
--json)`); `apply-and-restart` has its own rule for the process it waits for (above): pass
`--wait-pid $$`.
