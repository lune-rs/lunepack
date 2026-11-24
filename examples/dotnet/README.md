# The .NET example app

A C# console app that does what the shell app of the end-to-end suite does, through the runtime's
command line only (`../../docs/RUNTIME.md`): `startup --json` first, then the marker file
`e2e-flags` (`crash-on-start`, `exit-without-confirm`, `slow-confirm <secs>`, `hold <secs>`),
`confirm --json`, and with `--update` the calls `check`, `download` and `apply-and-restart`. It writes
one line `<tree version> <outcome>` per step to the file named by `LUNEPACK_E2E_OUT` and its real
path to `LUNEPACK_E2E_DETAIL` (nothing is written when a variable is unset).

It finds `lunepack-runtime` beside its own executable (`Environment.ProcessPath`), and its tree by
walking up to `lunepack-update.json`. It starts the runtime with an argument list, reads JSON Lines with
`System.Text.Json` and never ends in an unhandled exception: a crash on start is `Environment.Exit(3)`.

## Build

```
scripts/build-example-dotnet.sh <target> <out-dir> [--macos-bundle <dir>]
```

publishes a self-contained folder of about 190 files for a lunepack target id (`linux-x86_64`,
`linux-aarch64`, `windows-x86_64`, `macos-aarch64`, `macos-x86_64`; not `macos-universal`: a
self-contained .NET app is built per architecture). Pack the folder with `Example` (`Example.exe` on
Windows) as the entry.

The project has no package reference and no lock file, so the pin is the SDK: `global.json` names
the exact version, and it decides the version of the runtime pack the publish downloads.

On macOS a signature of a file that is not Mach-O is kept in an extended attribute, which a pack does not
carry. `--macos-bundle` therefore builds the bundle with the host alone in `Contents/MacOS` and every other
file under `Contents/Resources/app`; the host's path to them is written by the SDK's own `CreateAppHost`
task (the `ExampleMacBundleHost` target of `Example.csproj`).
