# The runtime's command line

Every version tree of an app that updates itself carries `lunepack-runtime`, placed beside the
app's entry executable by `lunepack pack --runtime` (`docs/CLI.md`). Besides the internal modes it
runs for the installer and the applier, it is a command line that an app in any language runs as a
child process to check for an update, download it, learn what happened since its last start and
confirm that it works. Each command is a thin layer over the library calls a Rust app makes
(`Updater::check`, `download` and `stage`, `startup`, `confirm_healthy`), so both get the same
behaviour and the same errors (D42). The decisions are M5-D11 and M5-D12 in `docs/DECISIONS.md`;
what the output must never hold is in `docs/THREAT-MODEL.md` ("The Linux runtime").

This page covers `check`, `download`, `startup` and `confirm`. `apply-and-restart` is documented with
its step of the milestone.

## Locating the runtime

The runtime is `lunepack-runtime` in the same directory as the app's entry executable (the
`install.entry` of `lunepack.toml`). An app finds it from its own resolved executable path
(`readlink -f "$0"` in a shell script), never through `current`, a shortcut, a command link or
`PATH`. It finds its tree by walking up from its own directory to the nearest
`lunepack-update.json` (`docs/FORMAT.md` 13), which holds the app id, the trusted root, the feed and
the channel: no argument supplies any of them. The feed must pass the feed rule of `docs/FORMAT.md`
13.3 (`https:`, `file:`, or `http:` to a loopback address only).

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

Global options, accepted by every command: `--json` (output JSON Lines instead of text) and
`--expect-schema <N>` (the schema the caller understands; anything but `1` is the error
`schema_mismatch`, before anything else happens).

The grammar is closed. Every option may appear once. An unknown option, a repeated one, an option
that does not belong to the command, a value that does not parse (a channel name outside the rule of
`docs/FORMAT.md` 10.5, a version that is not in its canonical text, a number with a sign or leading
zeros), a missing value, the `--option=value` form and any stray word are a usage error: exit code 2,
before any action (no lock, no state read, no network). The refusal names nothing of the arguments:
one fixed line on stderr, or, when `--json` stands before any `--`, the `error` object below with
`command` and `tree_version` null. `download` never takes an update description from its caller:
`--expect-version` only names the version the app expects, and any other candidate is the error
`unexpected_version`, never a downgrade.

`startup` takes everything after `--` as the arguments the app was started with. They matter only
when the start rolls back, because the previous version is then started with them.

## Output

With `--json`, stdout holds only UTF-8 JSON Lines, one object per line, each with `"schema":1` and a
`type`. Zero or more `progress` objects come first, then exactly one final object, `result` or
`error`. Changes within schema 1 are additive: a reader ignores members it does not know.

```json
{"schema":1,"type":"progress","phase":"download","done":1048576,"total":5242880,"file":null}
{"schema":1,"type":"progress","phase":"stage","done":7,"total":70,"file":{"path":"bin/app","done":3,"total":9,"source":"range"}}
{"schema":1,"type":"result","command":"download","tree_version":"1.0.0","version":"1.1.0","staged":true}
```

`progress`: `phase` is one of `check`, `scan`, `download`, `stage` (and, in the runtime's own log,
`install`, `wait`, `apply`, `launch`, `confirm`, `rollback`, `uninstall`); `done` and `total` are
non-negative integers (bytes, 0 when unknown); `file` is null or `{path, done, total, source}` with
`path` the signed relative path and `source` one of `unchanged`, `range`, `full_pack`. At most ten
progress lines a second are written, and every phase shows. Without `--json`, progress is at most one
line a second on stderr and the final line is one human line on stdout (an error goes to stderr).

`result` members, after `command` and `tree_version`:

| Command | Members |
|---|---|
| `check` | `update`: `null`, or `{version, download_size_max, time_checked}` (`time_checked` is false when the clock was implausible and expiry checks were skipped) |
| `download` | `version` and `staged`: the staged version and `true`; or `null` and `false` when the channel offers nothing new |
| `startup` | `events`: `[{kind: "installed", version}, {kind: "updated", from, to}, {kind: "first_run", version}, ...]`, oldest first; `action`: `"continue"` or `"exit"`; `pending` |
| `confirm` | `outcome`: `"confirmed"` or `"nothing_pending"` |

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
| 4 | `busy` | another lunepack operation holds the install lock |
| 5 | `cancelled` | the operation was cancelled, or stdout stopped accepting output |
| 6 | `stale` | the update is no longer applicable |
| 7 | `verify` | a document, hash or signature was refused |
| 8 | `transport` | the feed or pack could not be fetched |
| 9 | `fs` | a filesystem operation failed |
| 10 | `state` | the install state failed or is newer than this build |
| 11 | `incomplete` | a download ended early |
| 12 | `nothing_staged` | nothing usable is staged |
| 13 | `schema_mismatch` | `--expect-schema` names another schema |
| 14 | `update_config` | the tree's update configuration is missing, invalid, or its feed breaks the feed rule |
| 15 | `unexpected_version` | the version found is not the one expected |
| 16 | `token_mismatch` | the health token is malformed or does not match |
| 17 | `machine_scope` | the install is per machine |
| 18 | `unsupported` | not supported on this platform |
| 19 | `process` | a process operation failed |
| 20 | `rolled_back` | (apply) the new version failed its health check and was rolled back |
| 21 | `wait_timeout` | (apply) the process waited for did not exit in time; nothing changed |
| 22 | `rollback_unavailable` | (apply) the previous version cannot be started; the new one stays pending |
| 23 | `already_installed` | (install) the install already has a current version |
| 24 | `integration` | (install, uninstall) the desktop integration failed or is in the way |
| 25 | `in_use` | (uninstall) a process still runs from the install |
| 26 | `install_mismatch` | (install, uninstall) the install is not the one this environment derives |
| 70 | `internal` | anything else (a worker panic, a library error this build does not know) |

The table lives in one place in the runtime (`crates/lunepack-runtime/src/modes.rs`) and is pinned
by `crates/lunepack-runtime/tests/golden/objects.jsonl`, one error object per kind.

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
--json)`); `apply-and-restart` has its own rule for the process it waits for.
