# Integrating an app written in any language

An app in any language, native or managed, installs and updates itself through one thing: a program
called `lunepack-runtime` that sits beside the app's own executable. The app runs it as a child process,
reads its output and acts on the result. There is no library to link and no binding. The command line is
the interface ([`RUNTIME.md`](RUNTIME.md) is its reference); this guide walks through it with a real
app, the .NET example in [`examples/dotnet`](../examples/dotnet/README.md).

A Rust app uses the facade crate instead and follows [`GETTING-STARTED.md`](GETTING-STARTED.md); both
guides produce the same packs, feeds and installs. The signing keys and how to keep them are in
[`KEY-CEREMONY.md`](KEY-CEREMONY.md).

Nothing here adds a rule of its own. Where a rule matters, the guide links to the page that states it:
[`CLI.md`](CLI.md) for the packager, [`RUNTIME.md`](RUNTIME.md) for the runtime and its output,
[`FORMAT.md`](FORMAT.md) for the documents.

## What the app has to do

Three things, in this order, every time it starts ([`RUNTIME.md`, "The health handshake"](RUNTIME.md#the-health-handshake-d43)):

1. **`startup`**, first thing in `main`. It delivers the events queued since the last start
   (`installed`, `first_run`, `updated`) and says whether to go on. `action` `"exit"` means this version
   was rolled back and the previous one has already been started in its place: the app ends at once.
2. **`confirm`**, once the app works. A new version is started with a health token in its environment
   and is rolled back unless it confirms; the child inherits the token, so the app passes nothing. With
   no pending launch `confirm` succeeds and does nothing, so the app may call it on every start.
3. **`check`, `download`, `apply-and-restart`**, when the app decides to update (on a timer, from a menu,
   at the user's request). `apply-and-restart` ends with the app exiting; the runtime does the rest.

That is the whole contract. The packaging side is the same as for a Rust app, with a folder of files in
place of one executable.

## How the blocks below were made

Every command block was run, in a scratch directory, with keys made at that moment; the output under it
is what the command printed. The session ran on a Linux machine of the `aarch64` architecture (use
`linux-x86_64` on an x86-64 machine), and the macOS blocks ran on a Mac. Conventions:

- 64-character hex values are shortened to `8 characters...4 characters` where they appear.
- The release directory is on the same machine, so the feed is a `file:///` URL, which the feed rule
  allows ([`FORMAT.md` section 13.3](FORMAT.md)). The session lives in `/srv/demo`; use your own absolute
  path. A real feed is an `https://` URL.
- Times, `seq` numbers and sizes are those of that session.
- A block marked "(not run: ...)" was not run, and says why.

## 1. The app and its folder

The example is a console program that does what a real app does, with no window: it calls `startup`,
acts on a marker file, calls `confirm`, and with `--update` runs `check`, `download` and
`apply-and-restart`. It writes one line `<tree version> <outcome>` per step to the file named by the
environment variable `LUNEPACK_E2E_OUT`, so that a run can be read afterwards
([`examples/dotnet/README.md`](../examples/dotnet/README.md)).

Publish it as a self-contained folder for the target you pack for:

```
scripts/build-example-dotnet.sh linux-aarch64 publish
...
```

(not run in the session's container: it needs the .NET SDK that `examples/dotnet/global.json` names and
the network; it ran on the build machine, and its last line says `191 files` for this target. The folder
was then given to the session.)

The folder is what `pack` takes, as it is to be installed; the entry is the file `Example`. Nothing in
it has to know about lunepack:

```
$ ls publish | head -4
ls publish | wc -l
Example
Example.deps.json
Example.dll
Example.runtimeconfig.json
191
```

## 2. Keys and configuration

The keys and the configuration are those of [`GETTING-STARTED.md`](GETTING-STARTED.md) steps 3 and 4,
with another app id; the session repeated them:

```
$ mkdir dotnet-demo
cd dotnet-demo
mkdir keys release
ROOT=$(lunepack keys gen keys/root 2>/dev/null | sed -n 's/^public: //p')
RELEASE=$(lunepack keys gen keys/release 2>/dev/null | sed -n 's/^public: //p')
lunepack init --app-id org.example.dotnet --root-key "$ROOT"
wrote lunepack.toml
wrote lunepack-state.json
```

Add to `lunepack.toml`:

```toml
[signers.root]
file = "keys/root.key"

[signers.release]
file = "keys/release.key"

[update]
feed = "file:///srv/demo/dotnet-demo/release/"
health_timeout_secs = 5

[install]
entry = "Example"
name = "Example"
bin = "example"
```

`health_timeout_secs` is how long a new version has to confirm; the default is 60 and the lowest
value is 5 ([`CLI.md`](CLI.md), "Configuration"). The session uses 5 so that the rollback below is quick.

```
$ lunepack keys set --release-dir release --release-key "$RELEASE" --sign root
change: a first key set: 1 key(s), threshold 1
keys.json: version 1, root 1, 1 key(s), threshold 1
```

## 3. The runtime

`pack --runtime` takes the runtime as a file and places it beside the entry. Where it comes from depends
on the target:

- **Linux and Windows.** `lunepack prebuilt fetch --target <target> --out <dir>` downloads the pinned
  runtime (and, for Windows, the stub) of this CLI's release and checks its size and SHA-256
  ([`CLI.md`](CLI.md), "`lunepack prebuilt fetch`"). A CLI built from the repository has nothing pinned
  and refuses; build the runtime from a checkout instead:
  `scripts/build-runtime.sh <linux-x86_64|linux-aarch64>` for a static Linux runtime
  ([`CLI.md`](CLI.md), "Building the runtime"). The session used that script, as in
  [`GETTING-STARTED.md`](GETTING-STARTED.md) step 5.
- **macOS.** A self-contained .NET app is built for one architecture, so it is packed for
  `macos-aarch64` or `macos-x86_64`. The runtime must match the pack's target: a Mach-O file of that
  architecture, and a fat file with both slices only for `macos-universal`
  ([`CLI.md`](CLI.md), "Self-updating apps"). A lunepack release carries the universal runtime
  (`macos-universal`) and one thin runtime for each architecture, so
  `lunepack prebuilt fetch --target macos-aarch64 --out <dir>` gives a thin app its runtime; from a checkout
  on a Mac, `scripts/build-runtime.sh macos-aarch64` builds it (below).

## 4. Pack, publish and install

```
$ lunepack pack --input publish --version 1.0.0 --target linux-aarch64 \
    --release-dir release --sign release --runtime lunepack-runtime
binary: --runtime is a local build
delta: base(s) none
assemble: copied publish
update: placed the runtime and the update config
code-sign: 0 item(s)
hash: 194 file(s), 0 dir(s), 0 symlink(s), 95858402 bytes
pack: 194 distinct file(s) encoded on 8 worker(s)
sign: manifest signed by 1 key(s)
verify: manifest, pack and 194 frame(s) ok
placed: release/1.0.0/linux-aarch64.pack
placed: release/1.0.0/linux-aarch64.manifest.json
totals: 194 file(s), 95858402 input bytes, 26636826 pack bytes
codec bcj-arm64+lzma2: 18
codec bcj-x86+lzma2: 80
codec lzma2: 96
```

194 files: the 191 of the folder plus the runtime, the update configuration and the third-party notices
that `pack` placed. The entry and the files that are executable in the folder keep their executable bit
([`CLI.md`](CLI.md), "Hosts and file kinds"). The feed, the setup file and the first install are as before:

```
$ lunepack feed add --release-dir release --channel stable --version 1.0.0 --sign release
lunepack setup release --version 1.0.0 --target linux-aarch64
./org.example.dotnet-1.0.0-linux-aarch64-setup --silent 2>/dev/null
verify: 1.0.0/linux-aarch64.manifest.json and its pack ok (194 frame(s))
placed: feed-stable.json (seq 1795581438000, 1 release(s), 1 manifest(s) verified)
setup: org.example.dotnet-1.0.0-linux-aarch64-setup (33019360 bytes)
{"schema":1,"type":"result","command":"setup","tree_version":"1.0.0","outcome":"installed","version":"1.0.0"}
```

The install is a tree of 194 files under `~/.local/share/org.example.dotnet/versions/1.0.0`, and the
runtime is in it, beside `Example`:

```
$ RT=~/.local/share/org.example.dotnet/versions/1.0.0/lunepack-runtime
ls ~/.local/share/org.example.dotnet/versions/1.0.0 | head -3
ls ~/.local/share/org.example.dotnet/versions/1.0.0 | wc -l
Example
Example.deps.json
Example.dll
194
```

## 5. Locating the runtime and the tree

The runtime is `lunepack-runtime` (`lunepack-runtime.exe` on Windows) in the same directory as the app's
entry executable. An app finds it from its own resolved executable path, never through `current`, a
shortcut, a command link or `PATH`; it never computes the install root itself
([`RUNTIME.md`, "Locating the runtime"](RUNTIME.md#locating-the-runtime)). The runtime finds its own tree
by walking up to the nearest `lunepack-update.json`, so no argument carries the app id, the root, the
feed or the channel.

The example resolves its own path with `Environment.ProcessPath` and follows links in it; it does not
use `AppContext.BaseDirectory`, the working directory or `PATH`. On macOS the managed files sit under
`Contents/Resources/app` while the host sits in `Contents/MacOS`, which is why the base directory would
point to the wrong place there.

## 6. Running the commands

The rest of this guide calls the runtime directly, as the app does. Each run below is the runtime's own
output; the exit code is the process's.

The grammar is closed ([`RUNTIME.md`, "Command line"](RUNTIME.md#command-line)): every option once, no
`--option=value`, no stray word. `--json` makes stdout hold only UTF-8 JSON Lines, each with
`"schema":1` and a `type`: zero or more `progress` objects, then exactly one final object, `result` or
`error` ([`RUNTIME.md`, "Output"](RUNTIME.md#output)). A reader ignores members it does not know. The
exit code is one number per error class, the same as the error object's `kind`
([`RUNTIME.md`, "Exit codes"](RUNTIME.md#exit-codes)).

The example reads it like this: it starts the runtime with an argument list and no shell, reads all of
stdout, keeps the last non-empty line as the final object and the process exit code as the status
(`examples/dotnet/Program.cs`):

```csharp
    // Runs the runtime with the arguments and no shell. Sets rc (the exit code) and last (the final
    // non-empty line of stdout, the result or error object). The runtime's stderr stays ours.
    private void Call(IEnumerable<string> arguments)
    {
        var info = new ProcessStartInfo(runtime)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            StandardOutputEncoding = Utf8,
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }
        using var process = Process.Start(info) ?? throw new InvalidOperationException("the runtime did not start");
        var text = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        rc = process.ExitCode;
        last = "";
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length > 0)
            {
                last = trimmed;
            }
        }
    }
```

### `startup`

```
$ $RT startup --json -- --demo
{"schema":1,"type":"result","command":"startup","tree_version":"1.0.0","events":[{"kind":"installed","version":"1.0.0"},{"kind":"first_run","version":"1.0.0"}],"action":"continue","pending":false}
```

Everything after `--` is the arguments the app was started with; they matter only when the start rolls
back, because the previous version is then started with them. `events` are oldest first and each is
delivered once: `installed` and `first_run` here, `updated` (with `from` and `to`) after an update.
`action` is `"continue"` or `"exit"`; `pending` says whether this version still waits for `confirm`.

### `confirm`

```
$ $RT confirm --json
{"schema":1,"type":"result","command":"confirm","tree_version":"1.0.0","outcome":"nothing_pending"}
```

`outcome` is `"confirmed"` when a pending launch was confirmed, `"nothing_pending"` otherwise. Exit 16
`token_mismatch` means the token in the environment is malformed or not this launch's. An app that does not
run `confirm` is rolled back (below).

### `check`

```
$ $RT check --json
{"schema":1,"type":"result","command":"check","tree_version":"1.0.0","update":null}
```

```
$ $RT check
check: no update
```

Without `--json` the final line is one human line. `update` is `null` or `{version, download_size_max,
time_checked}`. After a 1.1.0 is packed and added to the feed (the same two commands as before, with
`--version 1.1.0`; their output is that of 1.0.0 plus the delta lines):

```
$ lunepack pack --input publish --version 1.1.0 --target linux-aarch64 --release-dir release --sign release --runtime lunepack-runtime
lunepack feed add --release-dir release --channel stable --version 1.1.0 --sign release
```

```
$ $RT check --json
{"schema":1,"type":"result","command":"check","tree_version":"1.0.0","update":{"version":"1.1.0","download_size_max":26636826,"time_checked":true}}
```

`check` only looks at the feed. `tree_version` is the version of the runtime that answered; every final
object names it, so an app can tell when it reached another version's runtime
([`RUNTIME.md`, "Locating the runtime"](RUNTIME.md#locating-the-runtime)).

### `download`

```
$ $RT download --json --expect-version 1.1.0
{"schema":1,"type":"progress","phase":"scan","done":0,"total":0,"file":null}
{"schema":1,"type":"progress","phase":"scan","done":95858972,"total":570,"file":{"path":"lunepack-update.json","done":570,"total":570,"source":"patch"}}
{"schema":1,"type":"progress","phase":"download","done":20,"total":20,"file":null}
{"schema":1,"type":"progress","phase":"stage","done":95858402,"total":95858402,"file":{"path":"lunepack-runtime","done":6296224,"total":6296224,"source":"unchanged"}}
{"schema":1,"type":"result","command":"download","tree_version":"1.0.0","version":"1.1.0","staged":true}
```

`download` runs `check`, then downloads and stages what it found. `--expect-version` names the version the
app expects; any other candidate is the error `unexpected_version` (exit 15), never a downgrade.
`progress` lines (at most ten a second) carry `phase`, `done`, `total` and, per file, `source`:
`unchanged` for a file the install already has, `patch` for one rebuilt from a delta, `range` or
`full_pack` for one downloaded. The size of this download is 20 bytes of patch: every file that did not
change was kept, and none was fetched again. With nothing new the result is `version` `null`
and `staged` `false`. An update the installed version's publisher policy refuses is exit 29
([`RUNTIME.md`, "Publisher continuity"](RUNTIME.md#publisher-continuity)).

### Errors

```
$ $RT check --bogus
echo "exit $?"
$RT --json check --bogus
echo "exit $?"
lunepack-runtime: usage error
exit 2
{"schema":1,"type":"error","command":null,"tree_version":null,"kind":"usage","exit_code":2}
exit 2
```

A usage error names nothing of the arguments, before any action. An error object has `kind` and
`exit_code`.

```
$ $RT check --json --expect-schema 2
echo "exit $?"
{"schema":1,"type":"error","command":"check","tree_version":null,"kind":"schema_mismatch","exit_code":13}
exit 13
```

`--expect-schema <N>` is how an app says which schema it understands; anything but `1` is
`schema_mismatch`, before anything else happens. An app that passes `--expect-schema 1` fails safe
against a future schema. The commonly met exit codes are 3 `not_installed` (a development run from the
build folder, or no install state), 4 `busy` (another lunepack operation holds the install lock), 7
`verify`, 8 `transport` (the feed or pack could not be fetched), 12 `nothing_staged` and 14
`update_config`; the full table, with every other code, is in
[`RUNTIME.md`](RUNTIME.md#exit-codes). The example treats every non-zero code of `check`, `download` and
`apply-and-restart` as one error (it logs `error check`, `error download` or `error apply`), and
`confirm`'s 16 as `error token-mismatch`.

### `apply-and-restart`

```
$ export LUNEPACK_E2E_OUT=/tmp/example.log
sleep 2 &
$RT apply-and-restart --json --wait-pid $! --expect-version 1.1.0 -- --after-update
{"schema":1,"type":"result","command":"apply-and-restart","tree_version":"1.0.0","version":"1.1.0","scheduled":true}
```

This starts the applier, which waits for the process named by `--wait-pid` (here a `sleep`, standing in
for the app) to exit, applies the staged version, and starts the new tree's entry with the arguments
after `--` and a fresh health token. The call returns at once with `scheduled: true`, and the app
exits next ([`RUNTIME.md`, "Apply and restart"](RUNTIME.md#apply-and-restart)). By default the runtime
waits for its own parent, which is the app only when the app runs the command itself; an app that runs it
through a wrapper, a shell, `env` or a launcher library passes its own pid with `--wait-pid`. The example
passes `Environment.ProcessId`. `--expect-version` is checked against what is staged, and `--no-ui` keeps
the update window from showing. The new version is started by the applier, not by the app's caller, so read
what it did from its own log. The example's:

```
$ cat /tmp/example.log
readlink ~/.local/share/org.example.dotnet/current
1.1.0 start
1.1.0 arg after-update
1.1.0 event updated 1.0.0
1.1.0 event first_run
1.1.0 confirmed
versions/1.1.0
```

(The block runs two commands; the log is the first six lines and `readlink` shows that `current` now
points at the 1.1.0 tree.) The new version started with `--after-update`, received the events `updated`
and `first_run`, and confirmed.

## 7. An app that never confirms is rolled back

An app that does not run `confirm` has every update rolled back: an unsupervised start of a pending
version counts an attempt and the fourth rolls it back; a supervised one is rolled back when it exits
badly or does not confirm within the health timeout ([`RUNTIME.md`, "The health handshake"](RUNTIME.md#the-health-handshake-d43)).
The example reads a marker file `e2e-flags` in its tree; `exit-without-confirm` makes it exit without
confirming. Ship a 1.2.0 with that file and let 1.1.0 update itself to it:

```
$ echo exit-without-confirm > publish/e2e-flags
lunepack pack --input publish --version 1.2.0 --target linux-aarch64 \
    --release-dir release --sign release --runtime lunepack-runtime | tail -n 2
lunepack feed add --release-dir release --channel stable --version 1.2.0 --sign release | tail -n 1
delta: from 1.1.0: 1 patch(es), 20 bytes for 356 bytes of frames
delta: from 1.0.0: 1 patch(es), 20 bytes for 356 bytes of frames
placed: feed-stable.json (seq 1795581473000, 3 release(s), 3 manifest(s) verified)
```

```
$ ~/.local/bin/example --update
```

The log was emptied before this run. Twenty seconds later:

```
$ cat /tmp/example.log
readlink ~/.local/share/org.example.dotnet/current
1.1.0 start
1.1.0 nothing-pending
1.1.0 check 1.2.0
1.1.0 staged 1.2.0
1.1.0 apply-scheduled
1.2.0 start
1.2.0 arg after-update
1.2.0 event updated 1.1.0
1.2.0 event first_run
1.2.0 exit-without-confirm
1.1.0 start
1.1.0 arg after-update
1.1.0 nothing-pending
versions/1.1.0
```

1.2.0 started, did not confirm, and after the five seconds of the health timeout the runtime started 1.1.0
again with the same arguments; `current` points at 1.1.0. The runtime's own log records it:

```
$ tail -n 2 ~/.local/share/org.example.dotnet/logs/runtime.log
{"schema":1,"type":"progress","phase":"rollback","done":0,"total":0,"file":null,"version":"1.2.0","reason":"timeout","time_ms":1795581483080}
{"schema":1,"type":"result","command":"apply","tree_version":"1.1.0","outcome":"rolled_back","version":"1.2.0","time_ms":1795581483096}
```

1.2.0 is marked bad on this install and is never offered again. The rule is the format's, not the
example's ([`FORMAT.md` section 11.4](FORMAT.md)).

## 8. Cancelling

End the child process. A download keeps its partial file and resumes on the next run. A runtime whose
stdout is closed or is no longer read cancels itself the same way and exits 5, so an app that stops
reading cancels the download too; a reader that never reads cannot stall it
([`RUNTIME.md`, "Cancel"](RUNTIME.md#cancel)).

(not run: a delta download is 20 bytes and ends before a signal could arrive.)

## macOS: the bundle layout

On macOS the input of `pack` is a ready `.app` bundle, `install.entry` is `Contents/MacOS/<file>`, and the
runtime is placed beside the entry in `Contents/MacOS` ([`CLI.md`, "macOS targets"](CLI.md#macos-targets-m8)).

A signed bundle cannot carry a file that is not Mach-O in `Contents/MacOS`: its signature lives in an
extended attribute, which a pack does not carry, so the installed bundle would not pass `codesign --verify
--deep --strict`. `pack` therefore refuses a bundle that is or will be signed when it has such a file
there, other than the main executable. A .NET app is managed `.dll` files plus a host, so the example
puts the host alone in `Contents/MacOS` and everything else under `Contents/Resources/app`, and the
host finds them from there. The host's path to the managed files is written by the SDK's own
`CreateAppHost` task in the project file (`examples/dotnet/Example.csproj`):

```xml
    <CreateAppHost AppHostSourcePath="$(AppHostSourcePath)"
                   AppHostDestinationPath="$(MacBundleHost)"
                   AppBinaryName="../Resources/app/$(AssemblyName)$(TargetExt)"
                   IntermediateAssembly="@(IntermediateAssembly->'%(FullPath)')"
                   EnableMacOSCodeSign="true" />
```

The script builds that bundle with `--macos-bundle`; the session ran it on a Mac (the layout is as the
script made it):

```
$ scripts/build-example-dotnet.sh macos-aarch64 out --macos-bundle out/Example.app
...
$ find Example.app -maxdepth 3 -not -path 'Example.app/Contents/Resources/app/*' | sort
ls Example.app/Contents/Resources/app | wc -l
Example.app
Example.app/Contents
Example.app/Contents/Info.plist
Example.app/Contents/MacOS
Example.app/Contents/MacOS/Example
Example.app/Contents/Resources
Example.app/Contents/Resources/app
     189
```

(The first command's own output names the paths of the build machine and is left out.) The thin runtime
comes from the script of [section 3](#3-the-runtime):

```
$ ./scripts/build-runtime.sh macos-aarch64 --out lunepack-runtime
...
built: target/aarch64-apple-darwin/release/lunepack-runtime
macho: yes (arm64; system libraries only)
minos: arm64=11.0
signature: ad hoc on every slice (codesign --verify --strict passes)
size: 6277888 bytes
```

(The first line of the script's output names the output path and is left out.) With the keys and
configuration of sections 2 and 3, and `entry = "Contents/MacOS/Example"`, `pack` takes the bundle:

```
$ lunepack pack --input Example.app --version 1.0.0 --target macos-aarch64 \
    --release-dir release --sign release --runtime lunepack-runtime
binary: --runtime is a local build
delta: base(s) none
assemble: copied Example.app
update: placed the runtime and the update config
code-sign: 0 item(s)
hash: 194 file(s), 4 dir(s), 0 symlink(s), 89010308 bytes
pack: 194 distinct file(s) encoded on 10 worker(s)
sign: manifest signed by 1 key(s)
verify: manifest, pack and 194 frame(s) ok
placed: release/1.0.0/macos-aarch64.pack
placed: release/1.0.0/macos-aarch64.manifest.json
totals: 194 file(s), 89010308 input bytes, 23206568 pack bytes
codec bcj-arm64+lzma2: 17
codec bcj-x86+lzma2: 80
codec lzma2: 97
```

The rule in action: the same bundle with a managed file put in `Contents/MacOS`, and a
`[codesign.macos]` section in the configuration (it is the signing tool's own argument list; `pack`
refuses before it runs it):

```
$ LUNEPACK_SIGN_IDENTITY=example lunepack --config lunepack-signed.toml pack --input Bad.app \
    --version 1.0.1 --target macos-aarch64 --release-dir release --sign release \
    --runtime lunepack-runtime
binary: --runtime is a local build
delta: base(s) 1.0.0
error: the bundle is or will be code-signed, but 1 file(s) under Contents/MacOS are not Mach-O executables: Contents/MacOS/Example.dll. The signature of such a file is kept in an extended attribute, which a pack does not carry, so the installed bundle would not verify. Move them under Contents/Resources (the app can find them from its own path there); only Mach-O files, and the main executable Contents/MacOS/Example, may sit in Contents/MacOS
```

An unsigned bundle with no `[codesign.macos]` section is packed as before. Signing, notarization and the
signed-bundle flow (`pack --assemble`) are in [`CLI.md`](CLI.md), "Code signing" and "Signed bundles".
The macOS install lives in `~/Applications` and `~/Library/Application Support/<app id>`
([`RUNTIME.md`, "macOS"](RUNTIME.md#macos)): an app is installed there by the installer app in the `.dmg` that
`lunepack setup` writes, and a bundle in a build folder, `~/Downloads` or the Desktop is a development
run, which `check` answers with exit 3.

(not run: installing on a Mac writes to the user's Applications folder and the launch services; the
repository's macOS suite does it under a temporary home.)

## Windows

On Windows the entry is `Example.exe`, the runtime is `lunepack-runtime.exe` beside it, and `pack` needs
`--stub` and a `windows-*` target ([`CLI.md`, "Windows targets"](CLI.md#windows-targets-m7)). The
shortcuts and the uninstall entry start the stub at the install root, which then starts the app; an app
finds its runtime from its own resolved executable path, never beside the stub. The Start-menu shortcut
carries the app id as its application user model id, and an app in another language sets the same id
itself, once, before it shows a window ([`RUNTIME.md`, "Windows"](RUNTIME.md#windows)). The example's
Windows folder comes from `scripts/build-example-dotnet.sh windows-x86_64 <dir>`.

(not run: this session had no Windows machine; the repository's Windows suite packs and installs this
same example.)

## A checklist

- Pack a folder with `[install] entry` and `--runtime` (and `--stub` on Windows); the feed in the config
  is the real one.
- Find the runtime beside the app's own resolved executable; do not compute the install root.
- At every start: `startup --json -- <your arguments>` first; end if `action` is `"exit"`.
- When the app works: `confirm --json`. Do it on every start; it does nothing when nothing is pending.
- To update: `check --json`, `download --json --expect-version <v>`, then `apply-and-restart --json
  --wait-pid <your pid> --expect-version <v> -- <arguments for the new version>`, then exit.
- Treat a non-zero exit as an error of its class; read the table in [`RUNTIME.md`](RUNTIME.md#exit-codes).
- Pass `--expect-schema 1` if the app should fail safe against a future schema.
- On macOS keep non-Mach-O files out of `Contents/MacOS`.
