# The C API

A C or C++ app updates itself through a library, `lunepack_ffi`, and one header, `lunepack.h`. The library is
a thin layer over the Rust facade: each function does what one command of the runtime's command line does
([`RUNTIME.md`](RUNTIME.md)), and nothing else. It adds no logic of its own, so an app that links it and an
app that runs `lunepack-runtime` as a child process ([`INTEGRATION.md`](INTEGRATION.md)) see the same
results, the same error classes and the same files on disk.

What the library does: the running app's own updater (check for an update, download it, stage it) and the
lifecycle calls (`startup`, `confirm_healthy`, `apply_and_restart`), with progress and cancellation. What it
does not do: install, uninstall, pack or sign (the packager and the runtime do those), and it takes no root,
feed URL or key from the caller. An app trusts only what its own signed tree carries
([`THREAT-MODEL.md`](THREAT-MODEL.md), "The C binding adds no trust input (M14)").

Status: the library is built from a checkout and is not distributed (not published to crates.io and not in a
release). Until the first distribution the function names and rules below may still change; from the first
one they are the promise under "The ABI promise".

A complete app is [`examples/c`](../examples/c/README.md), which runs the same end-to-end rows as the shell
and .NET apps on Linux, macOS and Windows.

## Building the library

```
cargo build --release --locked -p lunepack-ffi
```

The Rust toolchain pinned in `rust-toolchain.toml` is installed by rustup on first use (the minimum is Rust
1.90). The output is in `target/release`:

| System | Library | Also |
|---|---|---|
| Linux | `liblunepack_ffi.so` | built for the host's target |
| macOS | `liblunepack_ffi.dylib` | install name `@rpath/liblunepack_ffi.dylib` |
| Windows (MSVC) | `lunepack_ffi.dll` | an import library, `lunepack_ffi*.lib`, to link against |

The header is `crates/lunepack-ffi/include/lunepack.h`. It is generated from the Rust source by
`cargo run -p xtask -- ffi-header`, checked in, and checked by the gate (`ffi-header --check` fails when it is
stale), so it always matches the library built from the same commit. It needs `<stdbool.h>`, `<stddef.h>` and
`<stdint.h>` and compiles as C99 and as C++.

`cargo run -p xtask -- build-example-c --out <dir> [--target <id>]` builds the library and the example and
places both side by side; it is the shortest working build line for each system
([`examples/c/README.md`](../examples/c/README.md)).

## Linking and placing the library

Compile with the header's directory on the include path and link `lunepack_ffi`. The library and the app
travel together in the folder you pack: the packager takes the folder as it is to be installed, with your
executable as the entry, and places `lunepack-runtime` beside the entry.

- **Linux.** `cc app.c -I<include> -L<target/release> -llunepack_ffi -Wl,-rpath,'$ORIGIN'`. With the rpath
  `$ORIGIN` the loader looks beside the executable, so put `liblunepack_ffi.so` in the same folder.
- **macOS.** `cc app.c -I<include> -L<target/release> -llunepack_ffi -Wl,-rpath,@executable_path`. The
  library's install name is `@rpath/liblunepack_ffi.dylib`, so the rpath decides where it is found. In an app
  bundle the executable is in `Contents/MacOS`; put the `.dylib` there beside it (the layout is in
  [`INTEGRATION.md`](INTEGRATION.md), "macOS: the bundle layout"); the example's macOS end-to-end row builds
  exactly that.
- **Windows.** Link the import library and ship `lunepack_ffi.dll` in the folder of the executable: Windows
  looks in the application's own folder first. MSVC: `cl /I<include> app.c /link /LIBPATH:<target\release>
  lunepack_ffi.dll.lib`, with the import library's file name as your toolchain produced it.

The library finds the runtime and the app's tree from the app's own executable, never from the working
directory or `PATH`, with the rules of [`RUNTIME.md`](RUNTIME.md) ("Locating the runtime"): the runtime is in
the same folder as the entry, and the tree is found by walking up from the executable to the nearest
`lunepack-update.json` (on macOS, the one in the bundle's `Contents/Resources`). No call takes a path. A
process that is not inside such a tree, a development run from the build folder for example, gets
`LUNEPACK_STATUS_UPDATE_CONFIG` from every call that needs the tree; treat it as "updates are off in this
run". On macOS an app that runs from a translocated or read-only location gets
`LUNEPACK_STATUS_UNSUPPORTED_LOCATION` instead.

## A first look

Every start, in this order:

```c
#include "lunepack.h"

LunepackStartup *start = NULL;
LunepackStatus st = lunepack_startup(NULL, 0, &start);   /* first thing in main */
if (st == LUNEPACK_STATUS_OK && lunepack_startup_should_exit(start)) {
    lunepack_startup_free(start);
    return 0;                       /* rolled back: the previous version is already running */
}
/* ... the app runs; once it works: */
uint32_t outcome = 0;
lunepack_confirm_healthy(&outcome);
```

and when the app decides to update:

```c
LunepackUpdater *up = NULL;
LunepackUpdateInfo *info = NULL;
LunepackDownloaded *dl = NULL;
LunepackStaged *staged = NULL;
if (lunepack_updater_open(NULL, &up) == LUNEPACK_STATUS_OK
    && lunepack_updater_check(up, NULL, NULL, NULL, &info) == LUNEPACK_STATUS_OK
    && info != NULL                                            /* NULL: no update */
    && lunepack_updater_download(up, info, NULL, on_progress, ctx, &dl) == LUNEPACK_STATUS_OK
    && lunepack_updater_stage(up, dl, NULL, NULL, NULL, &staged) == LUNEPACK_STATUS_OK) {
    lunepack_apply_and_restart(lunepack_staged_version(staged), 0, NULL, 0);
    /* the call returns; the app must exit now */
}
/* free what is not NULL: staged, info, up (dl was consumed by stage) */
```

The complete version, with every free and every status, is [`examples/c/example.c`](../examples/c/example.c).

## The ABI promise

`LUNEPACK_ABI_VERSION` in the header is `1`, and `lunepack_abi_version()` returns the version the loaded
library implements; compare the two at start-up when the library and the header can come from different
builds. Within one ABI version changes are additive only: new functions, statuses, phases, sources, reasons,
flag bits, and fields appended to structs that the library allocates. Removing or re-meaning anything bumps
the version. So a caller must tolerate values it does not know: an unknown status is a failure, an unknown
phase or source number is shown as unknown (`lunepack_phase_name` and `lunepack_source_name` return NULL for
it), an unknown event kind is skipped. The promise binds from the first distribution; the library is not
distributed yet, so until then it may still change.

## Ownership

- A handle (`LunepackUpdater`, `LunepackUpdateInfo`, `LunepackDownloaded`, `LunepackStaged`,
  `LunepackStartup`, `LunepackCancelToken`) is allocated by the library and released by its `_free`
  function. Passing NULL to a `_free` does nothing. A freed handle must not be used again.
- A function that makes a handle writes it to the caller's `out` slot. The slot is set to NULL first, so
  after any failure it holds NULL and is safe to pass to a `_free`. A NULL `out` is `usage`.
- An output string is UTF-8, NUL-terminated and borrowed: it stays valid and unchanged until the handle it
  came from is freed. Copy it to keep it. The names (`lunepack_status_name`, `lunepack_phase_name`,
  `lunepack_source_name`, `lunepack_library_version`) and `lunepack_last_error_reason` return static
  strings that are valid for the life of the process.
- An input string is NUL-terminated UTF-8, read only during the call. Text that is not UTF-8 is `usage`.
  On Windows, `main`'s `argv` is in the ANSI code page, not UTF-8, so do not pass it as is: give
  `lunepack_startup` and `lunepack_apply_and_restart` strings you converted to UTF-8 (from
  `CommandLineToArgvW` with `WideCharToMultiByte(CP_UTF8, ...)`), or for `lunepack_startup` pass
  `(NULL, 0)` and let the library read the process's own arguments, as the example does.
- `lunepack_updater_stage` consumes its `LunepackDownloaded` whenever it is not NULL, whatever the status:
  do not free or reuse it afterwards. A downloaded handle that is never staged is released with
  `lunepack_downloaded_free`.
- The library never frees memory the caller owns and never keeps a pointer the caller gave it past the call
  that took it (the callback's `user_data` is used only during the call).

## Threads and callbacks

- Every call blocks the calling thread until it is done. An app with a window calls the long ones
  (`check`, `download`, `stage`) from a worker thread.
- `LunepackUpdater` and `LunepackCancelToken` may be used from several threads at once; two operations on
  one updater at the same time give one of them `LUNEPACK_STATUS_BUSY`. Result handles are immutable and may
  be read from several threads. A `LunepackDownloaded` has one owner at a time: it may move to another
  thread, never be used from two at once.
- A progress callback (`LunepackProgressFn`) runs on the thread that made the call, only during the call, so
  it needs no locking of its own for state that thread owns. Its `LunepackProgress` argument is valid during
  the callback only: copy what you need, keep no pointer from it (`file_path` included).
- A callback must not unwind and must not `longjmp` out (a C++ exception or a `longjmp` through the library's
  frames is undefined behaviour). While a callback runs, every function that returns a status refuses with
  `LUNEPACK_STATUS_USAGE`, so a callback cannot start a second operation or re-enter the library (the plain
accessors and the name lookups are not refused). The one
  way to react is the cancel token: `lunepack_cancel_token_cancel` and `lunepack_cancel_token_is_cancelled`
  work from inside a callback and from any thread, and the running call then ends with
  `LUNEPACK_STATUS_CANCELLED`. A download that was cancelled or ended early keeps its part, and the next
  `lunepack_updater_download` continues it.
- Free a handle only when no call that uses it is still running. A cancel token passed to a call must stay
  alive until the call returns.

## Errors

Every function that can fail returns a `LunepackStatus` (`int32_t`): `LUNEPACK_STATUS_OK` (0) or the number of
an error class. The numbers and names are the runtime's exit codes and `kind` names, so one table serves both:
[`RUNTIME.md`, "Exit codes"](RUNTIME.md#exit-codes). The header names a constant for each class that these
calls can return, `LUNEPACK_STATUS_<KIND IN UPPER CASE>` (`LUNEPACK_STATUS_BUSY` is 4, the runtime's `busy`),
and `lunepack_status_name` returns the runtime's `kind` string for a number, `"ok"` for 0, and NULL for a
number it does not know. Two classes exist only here: `usage` (2) is a bad argument (a NULL where a value is
required, text that is not UTF-8, a value outside its set, an unknown flag bit) or a call made from inside a
progress callback, and `internal` (70) is a caught panic, a worker failure or an error this library version
does not know.

Three classes carry a finer reason, which `lunepack_last_error_reason()` returns for the calling thread:
`unsupported_location` (28), `publisher_mismatch` (29) and `service_unavailable` (32), with the strings the
runtime's table lists. Every function that returns a status clears the reason on entry, so read it right
after the call that failed. It is NULL when the last call had no reason or succeeded.

There is no message text. A facade error's text may carry a path or the words of an operating-system error,
and no output of lunepack shows those (the runtime's JSON does not either, [`RUNTIME.md`](RUNTIME.md)).
Log the status number, its name and the reason; that is all the library will tell you.

The mapping from the facade's errors to these classes is written twice, here and in the runtime, because the
runtime is a binary crate; a unit test in the runtime holds the two equal, so they cannot drift.

### Panics

Every entry point runs inside `catch_unwind`, so a Rust panic never unwinds into your C frames: the call
returns `LUNEPACK_STATUS_INTERNAL` (or the neutral value of an accessor: NULL, 0 or false), and the panic's
payload is discarded and never printed by the library. The library installs no global panic hook, because a
hook would change the host app. Rust's default hook therefore still writes the panic message to standard
error at the moment of the panic, before it is caught. A panic that did escape an entry point would abort
the process (Rust never unwinds out of an `extern "C"` function); none is expected to.

## Functions

Every function the header declares is in this table, once. Those marked "Status" return a `LunepackStatus`
and clear the thread's reason on entry; the others return a value and cannot fail.

| Function | What it does |
|---|---|
| `lunepack_abi_version` | The ABI version the loaded library implements (`uint32_t`). |
| `lunepack_library_version` | The library's own version as text, for example `"0.1.0"`. Static. |
| `lunepack_phase_name` | The name of a phase number (`"check"`, `"download"`, ...); NULL if unknown. Static. |
| `lunepack_source_name` | The name of a file-source number (`"unchanged"`, `"range"`, `"full_pack"`, `"patch"`); NULL if unknown. Static. |
| `lunepack_status_name` | The name of a status number (`"ok"`, `"busy"`, ...); NULL if unknown. Static. |
| `lunepack_last_error_reason` | The reason name of this thread's last failed call, or NULL. Static. |
| `lunepack_cancel_token_new` | Makes a cancel token that is not cancelled; NULL only when it cannot allocate. |
| `lunepack_cancel_token_cancel` | Cancels the token and wakes what waits on it. Any thread; allowed inside a callback. NULL does nothing. |
| `lunepack_cancel_token_is_cancelled` | Whether the token was cancelled. Any thread; allowed inside a callback. NULL is not cancelled. |
| `lunepack_cancel_token_free` | Releases a token. No running call may still hold it. |
| `lunepack_startup` | The start of the running app: call it first at every start. Reconciles the install, counts this start while the version awaits its health check, delivers the queued lifecycle events once each, and sets `should_exit` after a rollback. Status. |
| `lunepack_startup_should_exit` | Whether the app must exit now: this version was rolled back and the previous one was started in its place. |
| `lunepack_startup_pending` | Whether this version still waits for `lunepack_confirm_healthy`. |
| `lunepack_startup_tree_version` | The running tree's own version, canonical SemVer text, borrowed from the handle. |
| `lunepack_startup_event_count` | How many lifecycle events were delivered, oldest first. |
| `lunepack_startup_event_kind` | The kind of event `i`: `LUNEPACK_EVENT_INSTALLED`, `LUNEPACK_EVENT_UPDATED` or `LUNEPACK_EVENT_FIRST_RUN`; 0 out of range. |
| `lunepack_startup_event_version` | The version event `i` is for (the new version of an update). Borrowed. |
| `lunepack_startup_event_from` | The version an update came from, for an `UPDATED` event; NULL for any other. Borrowed. |
| `lunepack_startup_free` | Releases a startup handle. |
| `lunepack_confirm_healthy` | The running version confirms its health. `out_outcome` gets `LUNEPACK_CONFIRM_CONFIRMED` or `LUNEPACK_CONFIRM_NOTHING_PENDING`; it is safe to call on every start. Status. |
| `lunepack_apply_and_restart` | Hands the staged version to the runtime, which waits for this process to exit, applies it and starts it. Returns; THE APP MUST EXIT NEXT. `expect_version` NULL or canonical text, `flags` `LUNEPACK_APPLY_NO_UI` and `LUNEPACK_APPLY_BACKGROUND`, `args` the new version's arguments. Status. |
| `lunepack_updater_open` | Opens the updater of the running app from its own tree's configuration; `channel` NULL is the configured one. Status. |
| `lunepack_updater_free` | Releases an updater. No operation may still run on it. |
| `lunepack_updater_check` | Checks the feed. `out` gets an update handle, or NULL when there is none (status ok both ways). Takes a cancel token and a progress callback, both optional. Status. |
| `lunepack_update_info_version` | The new version as canonical SemVer text. Borrowed. |
| `lunepack_update_info_download_size_max` | The most bytes a download of this update fetches (the pack's signed size). |
| `lunepack_update_info_time_checked` | Whether expiry and key windows were checked; false when the clock was implausible and they were skipped. |
| `lunepack_update_info_free` | Releases an update handle. |
| `lunepack_updater_download` | Downloads the update into the cache, resumably. `out` gets a downloaded handle. Takes a cancel token and a progress callback. Status. |
| `lunepack_downloaded_free` | Releases a downloaded handle that was not staged. |
| `lunepack_updater_stage` | Builds the new version's tree from the download and verifies it. Consumes the downloaded handle. `out` gets a staged handle. Takes a cancel token and a progress callback. Status. |
| `lunepack_updater_staged` | The version staged in this install, if any: `out` gets a handle, or NULL when nothing is staged. Status. |
| `lunepack_staged_version` | The staged version as canonical SemVer text. Borrowed. |
| `lunepack_staged_publisher` | What the publisher check reported when it let this version through, or NULL (no finding, or a handle from `lunepack_updater_staged`). Static. |
| `lunepack_staged_free` | Releases a staged handle. |

Accessors of a NULL handle return their neutral value (NULL, 0 or false) and never crash. The status
functions refuse a NULL where a handle or an `out` slot is required with `LUNEPACK_STATUS_USAGE`.

### Constants

The header also defines, with these prefixes: `LUNEPACK_STATUS_*` (above), `LUNEPACK_PHASE_*` and
`LUNEPACK_SOURCE_*` (the `phase` and `file_source` fields of `LunepackProgress`), `LUNEPACK_EVENT_*` (the
kinds of `lunepack_startup_event_kind`), `LUNEPACK_CONFIRM_*` (the outcome of `lunepack_confirm_healthy`) and
`LUNEPACK_APPLY_*` (the flag bits of `lunepack_apply_and_restart`). A phase is what the runtime's progress
lines call it ([`RUNTIME.md`](RUNTIME.md), "Output"). Progress events come only from the calls that take a
callback; a `check` reports progress only when it adopts a macOS bundle.

## What is not in ABI 1

Not in this version: `install`, `install_from_payload`, `installed`, the adoption flag of `check`,
`follow_move`, `wait_for`, and any constructor that takes a root, a feed URL or a layout. A C app's trust
comes only from its signed tree, as for the command line, so there is no way to point the library at another
feed or key. Each of these can be added later as a new function without breaking this version. A static
library is not built either: its native link line differs per system and nothing here would test it.

## Proof

`crates/lunepack-ffi/tests` runs the calls over the in-memory fakes of the test kit (every status, every
handle freed, the callback rules, cancellation and a panic caught at the boundary), and
`tests/c_example.rs` compiles [`examples/c/example.c`](../examples/c/example.c) as C99 with warnings as
errors against the library of the test build and runs its self-test on Linux, macOS and Windows. The same C
app is a row of each end-to-end suite and installs, updates, rolls back and uninstalls for real
([`INTEGRATION.md`](INTEGRATION.md), "An app in C").
