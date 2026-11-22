# lunepack CLI

`lunepack` packages an app's build output into a signed release directory that any static host can
serve, and checks such a directory the way a client does. The directory layout, the documents and
the signatures are defined in [`docs/FORMAT.md`](FORMAT.md); the decisions behind the tool are
M3-D1 to M3-D13 and M3-R1-D1 in [`docs/DECISIONS.md`](DECISIONS.md); what it defends against is in
the packager section of [`docs/THREAT-MODEL.md`](THREAT-MODEL.md).

Exit codes: 0 on success, 1 when a command fails or a check does not hold, 2 on a usage error.
Errors print as `error: <message>` on stderr. Progress and results print on stdout. No command prints
a private key, an environment variable's value or a config value.

Global option, accepted by every command: `--config <path>` (default `./lunepack.toml`).

## Packaging any app

The packaged app is an opaque build-output directory (M3-D13). `pack` is given:

- the directory (`--input`): the app's files as they should be installed, from any language or build
  system;
- the app id: from `lunepack.toml` (`--app-id`, when given, must equal it);
- the version and the target: flags, `--version` and `--target`.

Nothing reads a `Cargo.toml` or any other build file of the app, runs cargo, rustc or any toolchain,
or infers the version or the target. Files are classified by their contents, never their names
(M3-D6): PE (`.exe`, `.dll`), ELF (executables and `.so`) and Mach-O (executables, `.dylib`, bundles)
get the matching filter whatever language produced them; files that are already compressed (zip, gzip,
xz, zstd, bzip2, 7z, lz4, PNG, JPEG, GIF, WebP, WOFF2, Ogg) are stored; everything else gets LZMA2. A
file is stored when no candidate is smaller than the file. How a non-Rust app learns that an update
exists and triggers it from inside the app is not decided yet (it belongs to the client milestone).

## Configuration: `lunepack.toml`

Written by `lunepack init`, read by every other command. It holds public keys and the places to find
signers; it never holds a key. Unknown fields are errors. A parse error names the file and the line
and never repeats the text of the line.

```toml
app_id = "org.example.hello"

[root]            # the compiled-in root: what clients trust first
version = 1       # default 1
threshold = 1     # root keys that must sign a key set or a root rotation
keys = [
    "<64 lowercase hex characters>",
]

# Signers, used as `--sign <name>`. Exactly one of these forms per signer:
[signers.root]
file = "root.key"                # PKCS#8 PEM file, relative to this file

[signers.ci]
env = "LUNEPACK_SIGNING_KEY"     # PKCS#8 PEM in an environment variable

[signers.hsm]
command = ["my-signer", "--slot", "1"]
public = "<64 lowercase hex characters>"   # the key the command signs for

# Optional: where the publisher state file lives, relative to this file.
# state = "lunepack-state.json"            # the default

# Optional, together: an app that updates itself (see "Self-updating apps" below).
[update]
feed = "https://updates.example.com/hello/"   # the release directory, as a client reaches it
channel = "stable"                            # default "stable"
health_timeout_secs = 60                      # default 60, 5..=3600
publisher_check = "enforce"                   # optional (M9): "off", "warn" or "enforce"; see "Code signing"

[install]
entry = "bin/hello"          # the executable, relative to the tree (required, must be exec)
name = "Hello"               # the display name (required)
comment = "Says hello"       # optional
publisher = "Acme"           # optional: shown beside "verified" by the installer; left out when unset
icon = "assets/hello.svg"    # optional: a .png or .svg file of the tree
categories = ["Utility"]     # optional: freedesktop category names
bin = "hello"                # optional: the name of the command-line link
terminal = false             # optional, default false
url_schemes = ["hello"]      # optional (M7-D3): URL schemes the app handles, at most 8
autostart = false            # optional (M7-D3): start when the user signs in, default false

[[install.file_types]]       # optional (M7-D3): at most 32; each ext, mime and name
ext = "hello"
mime = "application/x-hello"
name = "Hello file"

[windows]                    # optional: inputs of the Windows stamp, not part of any signed document
icon = "assets/hello.ico"    # an .ico file, relative to this file

[macos]                      # optional: inputs of the macOS update window's helper app, not signed
icon = "assets/hello.icns"   # an .icns file, relative to this file; read only with --ui on a macos-* target

[codesign.windows]           # optional (M9): how a release is signed with the OS's code signing, as argv
                             # templates with no shell, always timestamped; see "Code signing"
sign = ["signtool", "sign", "/fd", "sha256", "/tr", "https://timestamp.example.com", "/td", "sha256",
        "{path}"]
[codesign.macos]             # optional (M9): the same for a macos-* target
sign = ["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp",
        "--sign", "{env:LUNEPACK_SIGN_IDENTITY}", "{path}"]
```

## The publisher state file (M3-R2-D1)

`lunepack-state.json`, next to `lunepack.toml` unless the config's `state` names another path (relative
to the config's directory). It records, per app id, what this publisher last signed or accepted: the
version of the root the last walk ended at, the version and threshold of the last `keys.json`, and the
`seq` of each channel's last feed. It holds these numbers only, never a key, a config value or a path.
`init` creates it (an existing file is checked and kept). `feed add`, `feed refresh`, `keys set` and
`keys rotate-root` update it, by temporary file and rename, after every document they place.

Why: the writers build on the previous documents in the release directory (the releases and rollouts
of the previous feed, the keys, windows and threshold of the previous `keys.json`), and they read them
with time checks skipped so an expired one can be renewed. A genuine but older document put back in the
directory would verify, and its values would be signed afresh with a new `seq` or version that clients
accept: a halted rollout undone, a dropped release listed again, a raised threshold lowered. The state
file is the publisher's own memory of what is current, kept where the release directory's writers
cannot reach it.

Before a writer builds on a previous document it compares the document with the record:

- equal, or newer (another trusted machine wrote since): it proceeds and records the new values;
- older than the record: it exits 1, writes nothing, and names the document, the recorded value and
  the value found ("the release directory may hold a replayed older copy"). `--allow-older-previous`
  builds on it anyway (recovery only), names each such document on stderr and records the new values;
- missing although recorded (a `keys.json` or `root-<k>.json` the state file records is not in the
  directory): treated like an older one. It exits 1, writes nothing, and names the document and the
  recorded value ("the release directory may be incomplete or tampered with"). Deleting `keys.json`
  would otherwise start the key set over at version 1, with a default threshold, under a record lowered
  to match. `--allow-older-previous` builds without it (to start over on purpose); `keys set` then
  requires `--threshold`, and the new key set's version 1 is below what clients that saw the old one
  accept, so restoring the missing file from the publisher's own storage is usually the better fix;
- no record (no state file, or a document it never saw, such as a feed of a channel another machine
  started): it exits 1 and writes nothing. `--trust-release-dir` accepts the directory's current
  documents as the baseline and records them. It trusts whatever the directory holds now, so use it only
  on a directory from the publisher's own storage. It does not cover a recorded document that is
  missing. A missing feed is the one exception: a feed that was removed can be started again with
  `feed add` (see Revoking a release key), and its new `seq` must still rise above the recorded one, or
  it exits 1 and writes nothing (`--allow-older-previous` overrides).

No writer lowers a recorded value (a root or `keys.json` version, a feed `seq`), or changes the recorded
threshold without a newer `keys.json`, unless `--allow-older-previous` is given; with it, each lowered
value is named on stderr. The record follows only what was placed.

One state file records one release directory per app: a second release directory of the same app
(staging and production, say) needs its own config directory or its own `state` path, or its writers
will be refused for the documents the other directory recorded.

Where to keep it: with the config, in the publisher's own storage. In CI, commit it next to
`lunepack.toml` and commit the update after each publish, or restore it from and save it to the CI's
own storage around the job. Never fetch the release directory from the public host (bucket, CDN or
mirror) as the base for writing without the state file: anyone with write access there can put an
older document back.

## Signer specs

`--sign <spec>` is repeatable. A spec is one of:

- `<name>`: a `[signers.<name>]` entry of the config;
- `file:<path>`: a PKCS#8 PEM key file;
- `env:<VAR>`: a PKCS#8 PEM key held in the environment variable `VAR`.

The distinct signers given must reach the threshold of the document being signed, and each must be a
key of the root (for `keys.json` and root documents) or of the key set (for manifests and feeds) and
inside its `not_before`..`not_after` window at the writer clock.

### Key file format (M3-D3)

A private key is Ed25519 as PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`, RFC 8410), the format `openssl
genpkey -algorithm ed25519` and most KMS and HSM exports use. `keys gen` writes it with `create_new`
(never over an existing file) and mode 0600 on Unix, and appends `.key` when the path has no
extension. On Unix a key file readable by group or others is refused at load. On Windows the file
inherits the ACL of its directory; lunepack neither sets nor checks it, so put keys in a directory only
you can read.

### Command signer protocol (M3-D4)

For a key that must not leave an HSM, KMS or signing service. The config gives `command` (an argv
vector, no shell) and `public` (the 32-byte Ed25519 public key as hex).

1. lunepack starts the command, writes the exact message to sign (the DSSE pre-authentication
   encoding of the document) to its stdin and closes it;
2. the command exits 0 and prints exactly 128 lowercase hex characters (the 64-byte signature),
   optionally followed by one newline, on stdout. lunepack reads at most 4 KiB;
3. lunepack verifies the signature against `public` before using it; a mismatch fails the command.

stderr is inherited and never captured or logged; the environment is inherited. An error names the
program (argv[0]) and the exit status only. Do not put a secret in the argv (it is visible to other
processes of the same user): pass it to the command through its environment.

## `SOURCE_DATE_EPOCH`

Commands that write documents (`keys set`, `keys rotate-root`, `pack`, `feed add`, `feed refresh`) take
"now" from `SOURCE_DATE_EPOCH` when it is set: ASCII decimal digits only, at most 2^53-1, otherwise the
command fails (the message names the variable and does not repeat its value). Without it they use the
system clock. `verify` and `inspect` use the system clock or `--at <unix>`; they ignore
`SOURCE_DATE_EPOCH`.

## Commands

### `lunepack init`

Writes a config with the compiled-in root and no signers; refuses to overwrite. Creates the publisher
state file next to it when there is none (an existing one is checked and kept).

```
lunepack init --app-id <APP_ID> --root-key <ROOT_KEYS> [--threshold <THRESHOLD>] [--config <CONFIG>]
```

- `--app-id`: lowercase letters, digits, `.`, `_`, `-`.
- `--root-key`: a root public key, 64 lowercase hex characters; repeat for several.
- `--threshold`: root keys that must sign (default 1).

### `lunepack keys gen`

```
lunepack keys gen <PATH> [--config <CONFIG>]
```

Writes a new private key file (see the key file format) and prints `public: <hex>` and `id: <hex>`
(the key id, SHA-256 of the public key) on stdout, nothing else.

### `lunepack keys show`

```
lunepack keys show --sign <SIGN> [--config <CONFIG>]
```

Prints the same two lines for a signer.

### `lunepack keys set`

Writes `keys.json`: exactly the listed release keys, signed by the root.

```
lunepack keys set --release-dir <RELEASE_DIR> --release-key <RELEASE_KEYS> --sign <SIGN>
    [--threshold <THRESHOLD>] [--not-before <NOT_BEFORE>] [--not-after <NOT_AFTER>]
    [--expires <EXPIRES>] [--allow-unverifiable-feeds] [--trust-release-dir]
    [--allow-older-previous] [--config <CONFIG>]
```

- `--release-key`: a release public key, 64 lowercase hex characters; repeat for several.
- `--threshold`: release keys that must sign a feed or manifest. Default 1 for a first key set (no
  `keys.json` and none recorded). When a `keys.json` exists, its threshold is kept only if the state
  file records the same value and the state check passed without an override; otherwise `--threshold`
  is required. It is also required when the state file records a key set that is missing (only
  reachable with `--allow-older-previous`).
- `--not-before`, `--not-after`: Unix times. A key already in the previous key set keeps its window
  unless these are given; a new key defaults to `now` .. `now` + two years.
- `--expires`: when the key set expires (Unix time); none by default.
- `--sign`: root signers; repeat to reach the root's threshold.
- The version is the previous version + 1.
- Before it places anything, `keys set` checks every `feed-*.json` in the directory, and every manifest
  each lists, against the new key set. If any would stop verifying it exits 1, places nothing and
  lists them (see Revoking a release key). `--allow-unverifiable-feeds` places `keys.json` anyway and
  names each feed that `verify` will now reject on stderr.
- Before placing, it prints one line on stdout, `change: version <n> -> <n+1>: ...`, naming what
  changes: the threshold, keys added and removed (by key id), changed windows and the expiry.
- The previous `keys.json` and the root walk are checked against the state file first;
  `--trust-release-dir` and `--allow-older-previous` as in The publisher state file.

### `lunepack keys rotate-root`

Writes `root-<k+1>.json` (signed by the current and the new root) and re-signs `keys.json` under the
new root (same keys and windows, version + 1). The root file is placed first.

```
lunepack keys rotate-root --release-dir <RELEASE_DIR> --new-root-key <NEW_ROOT_KEYS>
    --new-threshold <NEW_THRESHOLD> --sign <SIGN> --sign-new <SIGN_NEW>
    [--allow-unverifiable-feeds] [--trust-release-dir] [--allow-older-previous] [--config <CONFIG>]
```

- `--new-root-key`: a public key of the new root; repeat for several.
- `--sign`: signers of the current root; `--sign-new`: signers of the new root; each side must reach its
  own threshold. A key in both roots may be given on either side or both; it signs once.
- It runs the same feed check as `keys set`, with the same `--allow-unverifiable-feeds` override, and
  the same state file check, with the same `--trust-release-dir` and `--allow-older-previous`.

Publish `root-<k+1>.json` before `keys.json` (see the upload order); clients walk the rotation from
their compiled-in root. The config keeps the original root, and `verify` walks the same way.

### `lunepack pack`

Packages a build-output directory into `<version>/<target>.pack` and `<version>/<target>.manifest.json`
in the release directory.

```
lunepack pack --input <INPUT> --version <VERSION> --target <TARGET> --release-dir <RELEASE_DIR>
    --sign <SIGN> [--app-id <APP_ID>] [--jobs <JOBS>] [--memory-budget-mib <MEMORY_BUDGET_MIB>]
    [--runtime <RUNTIME>] [--ui <UI>] [--stub <STUB>] [--service <SERVICE>] [--config <CONFIG>]

lunepack pack --input <INPUT> --version <VERSION> --target <macos-TARGET> --runtime <RUNTIME>
    [--ui <UI>] --assemble <DIR> [--config <CONFIG>]
```

- `--version`: SemVer 2.0.0, used verbatim as the directory name. A directory of equal precedence with
  other text (they differ only in build metadata) is refused.
- `--target`: one of `windows-x86_64`, `windows-aarch64`, `macos-x86_64`, `macos-aarch64`,
  `macos-universal`, `linux-x86_64`, `linux-aarch64`.
- `--jobs`: encoder threads (default: the available parallelism). The output does not depend on it.
- `--memory-budget-mib`: memory budget of the encoders (default 2048). A file that needs more than the
  whole budget is encoded alone.
- `--app-id`: when given, it must equal the config's.
- `--runtime`: the static runtime to place beside the entry. Required when the config has `[update]`,
  refused without it (see "Self-updating apps").
- `--ui`: the `lunepack-ui` binary to place beside the runtime (for a `macos-*` target, inside the update
  window's helper app, see "macOS targets"). Needs `--runtime` and `[update]`, and is refused without
  them. Without it no UI is placed. A file over 64 MiB is refused.
- `--stub`: the Windows launcher stub, stamped and placed beside the entry as `lunepack-stub.exe`.
  Required for a `windows-*` target when the config has `[update]`; refused for any other target and
  without `[update]`. The console stub is needed when `install.terminal` is set, the GUI stub
  otherwise. A file over 32 MiB is refused.
- `--service`: the update service (M10-D7, M11), placed beside the entry as `lunepack-service.exe` for a
  `windows-*` target, and as `lunepack-service` for a `linux-*` target beside the entry or, for a
  `macos-*` target, at `Contents/MacOS/lunepack-service` (nested code, signed before the bundle).
  Needs `--runtime` and `[update]`, and is refused without them. Optional: without it the app installs
  for the user only and the installer offers no "For all users" choice. The file must be an image of
  the target that passes the checks a runtime passes (for Windows, a console-subsystem image that passes
  the hardening checks of a Windows runtime); a file over 32 MiB is refused. The target's service name
  (any letter case on Windows and macOS, exact on Linux) is reserved at any depth of the input tree, as
  `lunepack-stub.exe` is for Windows, with or without `--service`.
- `--assemble <dir>`: for a `macos-*` target with `[update]` (below): write the tree `pack` would hash to
  the new directory `<dir>` and stop, so it can be code-signed and then packed. It takes no
  `--release-dir` and no `--sign` (giving either is a usage error), reads no key and writes nothing to a
  release.

Pre-checks run before any encoding: `keys.json` verifies; every `--sign` key is in the key set and
inside its window; the signers reach the threshold; the manifest and pack do not exist yet; the target
is valid for this host (below).

The stages, in order (C2): (1) assemble: copy the input into a temporary directory (removed on success
and on every error); (2) code-sign: the OS sign stage, the developer's argv templates run over the items of the sign plan,
inner to outer, when the config has a `[codesign.<os>]` section for the target's OS ("Code signing"),
nothing otherwise; (3) hash every file; (4) pack: choose the smallest codec per file, round-trip it through the decoder a client uses,
and lay the frames out; (5) sign the manifest. `pack` then verifies its own output the way a client
does (a throwaway feed signed by the same signers, `verify_manifest`, the pack against the manifest's
size and SHA-256, every frame decoded) and only then writes the pack and, last, the manifest. Neither is
ever overwritten. Stdout has one line per stage and the totals: files, input bytes, pack bytes, files
per codec and the candidates that were dropped, with reasons.

Hosts and file kinds (M3-D10): `exec` is taken from the Unix mode (`mode & 0o111 != 0`). A Windows host
cannot know the bits, so it marks no file executable and refuses `linux-*` and `macos-*` targets.
Special files (fifo, socket, device) are refused everywhere. Hard links are packed as files; symlinks
are packed as links and must satisfy FORMAT 10.2 (symlinks exist only on `linux-*` and `macos-*`
targets; a `windows-*` pack with a symlink is refused).

### Self-updating apps: `[update]`, `[install]` and `--runtime` (M5-D7)

An app that updates itself carries the runtime and a configuration in its tree. Both are written by
`pack`, so the manifest's hashes cover them and the signed release vouches for them (FORMAT.md 13).
Without `[update]` the tree is packed exactly as above, for apps that do not update themselves.

With `[update]` (and then `[install]`, which is required; `[install]` without `[update]` is an error):

- `--runtime <path>` is required. The file must match the target: for `linux-*`, a 64-bit ELF of the
  target's machine (x86-64 or aarch64) with no `PT_INTERP`, meaning statically linked (a static-pie
  executable passes); for `windows-*` a PE (hardened, see below) and for `macos-*` a Mach-O of the
  target's architecture (`macos-universal`: a fat file with both slices; a header check only).
  Anything else is refused.
- After the input is copied and before code signing and hashing, `pack` copies the runtime to
  `<directory of install.entry>/lunepack-runtime` (`lunepack-runtime.exe` for `windows-*`), marked
  executable, and, with `--ui`, the UI to `<directory of install.entry>/lunepack-ui` (`lunepack-ui.exe`
  for `windows-*`), also marked executable. A `linux-*` UI may be dynamically linked (glibc); the
  runtime may not. The UI's bytes are checked against the target's format and machine, like the
  runtime's. Then it writes the update configuration at the tree's root, `lunepack-update.json`
  (`Contents/Resources/lunepack-update.json` for `macos-*`, FORMAT.md 13.1). The configuration holds
  the app id and root from `lunepack.toml`, the `--version` and `--target` of this pack, the feed, the
  channel, the health timeout and the install metadata. It holds no timestamp. Stdout gets one
  `update:` line.
- The entry and the icon must be regular files of the input tree (not symlinks, nor behind one), and
  on a non-Windows target the entry must carry the exec bit. An error names the field, `install.entry`
  or `install.icon`, never its value.

Reserved names, each an error before anything is written:

- a file or directory named `lunepack-update.json` (any case) at any depth of the input, so nothing
  can shadow the root configuration when an executable looks for the nearest one above itself;
- a file named `lunepack-runtime` or `lunepack-runtime.exe` (any case) in the entry's directory, or a
  file named `lunepack-ui` or `lunepack-ui.exe` there, with or without `--ui`: the runtime starts a
  UI from its own directory, so the name is never left to an app file.

The feed (`[update] feed`) must pass the feed rule of FORMAT.md 13.3, which `pack` checks with the same
function a client runs before its first request: `https://` with a lowercase DNS name or an IPv4
address, `file:///`, or `http://` to a loopback IP literal (`127.x.y.z` or `[::1]`) only; no user
information, query, fragment, percent-encoding, uppercase or non-canonical form; a trailing `/` is
added when missing. `http://` to any other host, `localhost` included, is refused: the error names
`[update] feed` and the rule that failed and never prints the feed.

Determinism (C2) covers the runtime too: the same inputs, runtime bytes, keys and `SOURCE_DATE_EPOCH`
give a byte-identical configuration, pack and manifest. `verify` accepts the result; `inspect` lists
the two files like any others.

Building the runtime: `scripts/build-runtime.sh <linux-x86_64|linux-aarch64>` runs the static musl
build (the target must be installed with `rustup target add`; `--print-command` shows the command and
runs nothing). `pack` does not build the runtime itself in M5; D19's build-from-source waits for a
published crate (M13).

`scripts/build-runtime.sh <macos-aarch64|macos-x86_64|macos-universal>` builds on a macOS host only (the
Apple linker, `lipo` and `otool`). `macos-universal` builds both slices and joins them with
`lipo -create`. The build sets `MACOSX_DEPLOYMENT_TARGET=10.15`, which binds the x86_64 slice only: the
aarch64 slice keeps Rust's own minimum, macOS 11.0, the first release for Apple silicon (M8-D14). The
binary is stripped and checked: the architectures are exactly the target's, `otool -L` lists
`/usr/lib` and `/System/Library` libraries only, and the x86_64 slice's minimum is 10.15; the script
prints both slices' minimums.

### Windows targets (M7)

A `windows-*` pack with `[update]` carries three more things, each written before hashing so the signed
manifest covers them (FORMAT.md 13, 15):

- `--stub <path>` is required: the launcher stub (`lunepack-stub.exe`, or `lunepack-stub-console.exe` when
  `install.terminal` is set). It is stamped (below) and placed in the entry's directory as
  `lunepack-stub.exe`; that name is reserved at any depth of the input. The runtime copies it to the install
  root under the entry's own file name.
- The runtime, the UI and the stub must be Windows executables of the target's machine, built hardened
  (a static C runtime, `DependentLoadFlags` 0x800 and an embedded manifest with `asInvoker` and
  `longPathAware`; the stub, the runtime and the UI are checked for the right subsystem). `pack` refuses one that
  imports a C runtime DLL (`vcruntime*`, `msvcp*`, `api-ms-win-crt-*`, `ucrtbase`) or imports `advapi32.dll`
  statically (it must be delay-loaded, so a planted `cryptbase.dll` is never loaded), or that lacks the flag
  or the manifest. The error names the file and the field, never a value.
- `install.name` must be a valid Windows folder and shortcut name (FORMAT.md 13.4: at most 64 UTF-16 code
  units, none of `< > : " / \ | ? *`, no control character, no leading or trailing dot or space, no device
  name), because the display name is the folder name of a first install. The error names `[install] name`
  and the clause, never the name. The rule is not applied to Linux or macOS targets.

**Stamping (M7-D14).** The stub and a Windows setup file's runtime get an icon and a VERSIONINFO resource,
written with `editpe`, a pure Rust crate (D17, M7-D22). The icon is `[windows] icon` when set (checked as
an ICO file: at most 64 images, at most 4 MiB), else `install.icon` when it is a PNG that is square and at
most 256 pixels (wrapped as a PNG-in-ICO entry without resampling), else none. A `.svg` `install.icon` or none
means no icon; a PNG that is not square or is larger is an error. The strings are `FileDescription` and
`ProductName` = `install.name` (the setup file's `FileDescription` is `<name> Setup`), `CompanyName` =
`install.publisher` when present, `FileVersion` and `ProductVersion` = the full version, and
`OriginalFilename` = the entry's file name (a setup file's: its own name); the numeric version is
`major.minor.patch.0`, and a component above 65535 fails the pack, naming `--version`. After stamping,
`pack` re-reads the output and refuses it if the machine, subsystem, import table, `DependentLoadFlags` or
manifest differ from the input's, naming the field. The stamp is a function of the input bytes and these
fields only, so two packs of the same input give the same bytes (C2).

**Windows setup files.** `lunepack setup` for a `windows-*` target takes the runtime out of the pack through
its signed frame, removes any certificate table, stamps it as above (its `OriginalFilename` is the file's
name) and appends the payload and the trailer, with nothing after it (FORMAT.md 14). The output is
`<app_id>-<VERSION>-<TARGET>-setup.exe` by default. With `[codesign.windows]` in the config, `setup` signs it
with the `sign_installer` template after it is built ("Code signing"); without it, sign the file yourself
with Authenticode. The runtime finds the trailer in a signed file (FORMAT.md 14.3), and a byte added after
the signature makes it refuse to run.

A Windows setup file also carries the **anchor** (FORMAT.md 14.5): one resource of the runtime image holding
SHA-256 digests of the trailer, the key-set part and the manifest part. `setup` stamps a placeholder, writes
the payload and the trailer, patches the digests in place and reads the file back against them; the file's
length and offsets do not change. An installer for all users checks its payload against the anchor of its own
running image. The anchor binds the payload after an administrator consented to the prompt; before consent
only an Authenticode signature lets the administrator tell a genuine setup file from a swapped one, so sign
the installer of an app that installs for all users. A release packed with `--service` offers the "For all
users" choice (RUNTIME.md, "Per-machine installs").

### macOS targets (M8)

A `macos-*` pack with `[update]` packs an app bundle (`<Name>.app`'s contents) and adds files inside it,
each written before hashing so the signed manifest covers them (FORMAT.md 13, 17):

- The input must hold `Contents/Info.plist` as a regular file, and `install.entry` must be
  `Contents/MacOS/<file>` (an executable regular file). The error names `Contents/Info.plist` or
  `[install] entry`, never the value.
- The runtime is placed beside the entry, `Contents/MacOS/lunepack-runtime` (marked executable), and the
  update configuration at `Contents/Resources/lunepack-update.json`.
- With `--ui`, the update window is a helper app (M8-D6): the UI binary at
  `Contents/Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui` (executable) with a generated
  `Contents/Info.plist` (`CFBundleExecutable` `lunepack-ui`; `CFBundleIdentifier` the app id with `_` written
  as `-`, then `.lunepack-update`; `CFBundleName` the `install.name`, XML-escaped; `CFBundlePackageType`
  `APPL`; `LSMinimumSystemVersion` `10.15`; `NSHighResolutionCapable`). The plist is a function of the app
  id, the name and whether there is an icon, so equal inputs give equal bytes. Nothing but the runtime sits
  in `Contents/MacOS` beside the entry. Without `--ui` no helper app is placed.
- `[macos] icon` is an `.icns` file (checked: the `icns` magic and a header length equal to the file's, at
  most 4 MiB) copied to the helper's `Contents/Resources/lunepack-update.icns`, which the plist names as
  `CFBundleIconFile`. It is read only with `--ui` on a `macos-*` target; elsewhere it is ignored. A bad file
  is refused naming `[macos] icon`, never its content.
- Reserved, each an error before anything is written: `Contents/Helpers/lunepack-update.app` and
  everything under it, `Contents/Resources/lunepack-setup.payload` (the installer app's payload file), the
  names `lunepack-update.json` (at any depth), and `lunepack-runtime` and `lunepack-ui` in
  `Contents/MacOS`. Comparison ignores ASCII case.
- Symlinks are packed as links, unchanged, and must satisfy FORMAT 10.2: a target stays inside the
  bundle, may pass through other links inside it (a framework's `Versions/Current` → `A` and `Foo` →
  `Versions/Current/Foo` pack as they are), and follows at most 8 of them. Exec bits come from the
  Unix mode.
- The installed bundle's name is `install.name` when it can be a file name: 1 to 200 UTF-8 bytes, no `/`,
  `:` or control character, no leading `.` (FORMAT.md 13.4). Otherwise it is the app id. `pack` still
  packs, and warns on stderr, naming the rule and never the name.

**Signed bundles (M8-D8).** `pack` never modifies a bundle that holds `Contents/_CodeSignature`, since any
change would break its seal. Such a bundle is packed as it is when every file `pack` would place is
already in it byte for byte (content and exec bit): the runtime and, with `--ui`, the helper's
executable, `Info.plist` and icon must be the files given to `--runtime`, `--ui` and `[macos] icon`, and
the config the one this version and target would get. The helper app's own signature may sit inside the
helper app. Otherwise `pack` fails before it writes anything, naming the first path that is missing or
different, and says to use `--assemble`. The flow: `pack --assemble <dir> ...` writes the assembled
bundle, with the same `--input`, `--version`, `--target`, `--runtime`, `--ui` and config as the pack; sign
that tree (inner code first); pack it with the same options, passing the signed copies of the runtime and
UI from the assembled tree as `--runtime` and `--ui` (signing rewrites a Mach-O file). `--assemble`
refuses a `<dir>` that exists, an input that is already signed, a target that is not `macos-*` and a
config without `[update]`; a failure removes the `<dir>` it created.

### Code signing: `[codesign.windows]` and `[codesign.macos]` (M9)

`pack` signs a release with the developer's own tools before it hashes the tree, and `setup` signs the
installers after they are built. lunepack runs the tool; the tool, the identity and the account are the
developer's. The sections apply only to targets of their own OS (a `[codesign.windows]` section is ignored
for a `macos-*` target); there is no Linux section, because the release signatures already cover a Linux
tree. Without the section for the target's OS nothing is signed and nothing about the pack changes.

```toml
[codesign.macos]
sign = ["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp",
        "--sign", "{env:LUNEPACK_SIGN_IDENTITY}", "{path}"]
verify = ["/usr/bin/codesign", "--verify", "--deep", "--strict", "{path}"]
notarize = ["/usr/bin/xcrun", "notarytool", "submit", "{zip}",
            "--key", "{env:LUNEPACK_NOTARY_KEY}", "--key-id", "{env:LUNEPACK_NOTARY_KEY_ID}",
            "--issuer", "{env:LUNEPACK_NOTARY_ISSUER}", "--wait"]
staple = ["/usr/bin/xcrun", "stapler", "staple", "{path}"]
```

**Keys** (every template is a non-empty array of strings; unknown keys are errors):

| Key | Meaning |
|---|---|
| `sign` | required: signs a Windows PE file or a loose macOS Mach-O file |
| `sign_bundle` | macOS, optional, default `sign`: nested bundles and, by default, the outer bundle |
| `sign_outer` | macOS, optional, default `sign_bundle`: the app bundle only, where its entitlements go |
| `sign_installer` | optional, default `sign`: what `setup` signs (`Setup.exe`, the installer app's items and the app, the `.dmg`) |
| `verify` | optional: run after a signature. Windows: on every PE file just signed; macOS: once, on the signed outer bundle |
| `notarize`, `staple` | macOS, both or neither: after `sign_outer` and `verify`, `notarize` (with `{zip}` or `{bundle}`), then `staple` on the bundle |
| `timeout_secs` | sign and verify, default 300, `1..=86400` |
| `notarize_timeout_secs` | macOS, default 3600, `1..=86400` |

**Templates (M9-D1).** An element is either literal text with no `{` or `}` at all, or exactly one
placeholder as the whole element: `{path}` (the absolute path of the item being processed), `{bundle}` and
`{zip}` (in `notarize` only: the bundle directory, or a zip of it that lunepack writes for the call and
removes after it, holding the bundle as `<bundle name>.app`), and `{env:NAME}` (`NAME` matches
`[A-Z_][A-Z0-9_]*`; the variable must be set and non-empty, else the pack fails before any tool runs).
`--file={path}` or `x{env:A}` is refused when the config loads, as is any other brace. `{path}`, `{bundle}`
and `{zip}` are never the program (`argv[0]`); `{env:NAME}` may be (a tool path from the environment).
Every path placeholder expands to an absolute path, so no expansion can be read as an option. There is no
shell and no quoting language: a template is an argument vector.

**No secret values in templates.** `{env:NAME}` puts the value on the tool's command line, which other
local users can read. It is for paths, key ids and identity names, never for a password, token or key
material. A secret reaches the tool through the tool's own environment or a file it reads (a keychain, a
password file, an API-key file kept outside every checkout). The key file of a notarization is a path in
`{env:}`; lunepack never reads it.

**How a template runs (M9-D3).** Every template, and `hdiutil`, goes through one runner: the program is
started directly (on Windows a `.bat` or `.cmd` program is refused, because `cmd.exe` would re-parse the
arguments), standard input is closed, standard output and error keep at most 64 KiB each, and the child is
killed after its timeout. Its environment is the packager's own, unchanged (tools need `PATH`, `HOME`,
`SystemRoot` and their own credentials). `pack` and `setup` print `code-sign: <relative path>` per item and,
on a failure, the template's key (`sign`, `notarize`, ...), the program's file name, the exit status or
"timed out" and at most the last 4 KiB of the tool's standard error with every `{env:}` value of that call
replaced by `<NAME>`. They never print the expanded arguments or any environment variable. After every call
lunepack checks that the item really changed into a signed form; a tool that exits 0 and changes nothing, or
signs another file, fails the pack with `code-sign: <relative path> is not signed after <key>` and nothing
is written to the release.

**What is signed (M9-D4).** On a `windows-*` target, every file of the tree whose header is a PE (the
header decides, not the extension) and that has no certificate table, deepest first; PE files that are
already signed (a third party's runtime DLL, the developer's own) are left as they are. A file that starts with
`MZ` and has `PE\0\0` where its `e_lfanew` points is a PE wherever that is, even past the first 64 KiB; one whose
headers lunepack cannot read (such a far-header image included) fails the pack instead of being left unsigned. On a `macos-*` bundle
with no `Contents/_CodeSignature`: for each nested bundle (`*.app`, `*.framework`, `*.appex`, `*.xpc`,
`*.bundle` and `*.plugin` directories under `Contents/`), deepest first, its loose Mach-O files and then the
bundle with `sign_bundle`; then the outer bundle's own loose Mach-O files (the main executable excluded);
then the outer bundle with `sign_outer`. The runtime, the helper update app and the UI binary are in that
order by construction. A bundle that already holds a signature (the signed-bundle flow above) is left
unchanged by the whole stage: the developer signed it, and notarizes it themselves if they want. A framework
with several `Versions/` directories signs only `Current`. The outer bundle's `{path}` and `{bundle}` name a
directory whose name ends in `.app`, so tools that dispatch on the suffix see a normal bundle; the
directory's name is internal and no output records it.

**Notarization and the staple ticket (M9-D5).** For a `macos-*` bundle, after the outer bundle is signed
and verified, `notarize` runs with `{zip}` or `{bundle}`, then `staple` on the bundle, then lunepack checks
that `Contents/CodeResources`, the ticket stapler writes, is a regular file in the tree. All of it happens
before hashing, so the ticket is a file of the signed release (a `staple` that writes none fails the pack).
`setup` signs the installer app's items and the app, notarizes and staples the app, builds the image, then
signs, notarizes and staples the `.dmg`: two notarizations. The `.zip` installer holds the bundle as
released.

**Publisher continuity (M9-D6).** The pack also writes the update configuration's `publisher_check` member
(FORMAT.md 13.2): the policy the *installed* version applies when it stages a later one (RUNTIME.md,
"Publisher continuity"). The default is `enforce` when the config has a `[codesign.<os>]` section for the
target's OS and `off` otherwise; an explicit `[update] publisher_check = "off" | "warn" | "enforce"` wins.
`off` is not written (the member is left out, so the bytes are those of a config without it). Under
`enforce` an update must be signed by the same OS code-signing publisher as the installed version, and the
installed app must really be signed: an unsigned or ad-hoc install has no baseline, and a tree whose files
carry no signature of the platform's kind is refused. Use `warn` while you are not sure your signing is in
place.

**Moving to another publisher.** If you change the certificate's subject (a renewal under another
organisation name, a move between certificate types, a new Developer ID team), installed apps under
`enforce` refuse the first release under the new identity and stay on the old one. Ship one release first
with `publisher_check = "warn"`, signed by the old identity; once your users run it, the next release can be
signed by the new identity, and their client reports the finding (`different`) and updates. A release signed
ad hoc, or by a tool that left it unsigned, is refused the same way (`candidate_unsigned`).

**Timestamps and expiry.** A signature made without a timestamp stops verifying when the certificate
expires (`CERT_E_EXPIRED` on Windows). Use a timestamp in every template: `--timestamp` for `codesign`
(notarization requires it anyway), `/tr <service> /td sha256` for `signtool`, `--tsaurl` for `jsign`. A
candidate signed with an expired, untimestamped certificate is refused as `candidate_invalid`; an *installed*
entry whose certificate has since expired does not block its own updates (THREAT-MODEL.md, "OS code signing
and publisher continuity (M9)"). The throwaway signatures of lunepack's own CI carry no timestamp, because
the tests have no network to a timestamp service.

**Example templates.** These use placeholder names. Each tool's own arguments are its own: check them against
the tool's documentation and your version. lunepack's tests run `codesign`, `xcrun notarytool` and `stapler`
(on a Mac, with ad-hoc and throwaway identities in CI and the developer's own in
`scripts/macos-sign-check.sh`) and `signtool` with a throwaway certificate; the others come from the tools'
documentation and are not run by lunepack's tests.

```toml
# macOS: codesign + notarytool + stapler (the section above); entitlements on the app bundle only:
sign_outer = ["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp",
              "--entitlements", "{env:LUNEPACK_ENTITLEMENTS}",
              "--sign", "{env:LUNEPACK_SIGN_IDENTITY}", "{path}"]
# (an identity looks like "Developer ID Application: Example Corp (TEAMID)", or is its hash)

# macOS: rcodesign (apple-codesign), a p12 file reference and the App Store Connect API key file.
# Untested since 2024 in this project; `{bundle}` lets the tool submit the bundle itself.
sign = ["rcodesign", "sign", "--p12-file", "{env:LUNEPACK_P12_FILE}",
        "--p12-password-file", "{env:LUNEPACK_P12_PASSWORD_FILE}",
        "--code-signature-flags", "runtime", "{path}"]
notarize = ["rcodesign", "notary-submit", "--api-key-file", "{env:LUNEPACK_NOTARY_API_KEY_FILE}",
            "--wait", "{bundle}"]
staple = ["rcodesign", "staple", "{path}"]
```

```toml
# Windows: signtool with a certificate in the user's store, identified by its SHA-1 thumbprint.
[codesign.windows]
sign = ["signtool", "sign", "/fd", "sha256", "/tr", "https://timestamp.example.com", "/td", "sha256",
        "/sha1", "{env:LUNEPACK_SIGN_CERT_SHA1}", "{path}"]
verify = ["signtool", "verify", "/pa", "{path}"]

# Windows: Azure Trusted Signing through signtool's dlib; the account's credentials live in the dlib's
# own environment, the metadata file names the account.
sign = ["signtool", "sign", "/fd", "sha256", "/tr", "https://timestamp.example.com", "/td", "sha256",
        "/dlib", "{env:LUNEPACK_AZURE_DLIB}", "/dmdf", "{env:LUNEPACK_AZURE_METADATA}", "{path}"]

# jsign with a PKCS#12 file: the password is read from the environment by jsign (`env:NAME` is jsign's
# own reference syntax, plain text to lunepack), never passed as an argument value.
sign = ["jsign", "--keystore", "{env:LUNEPACK_P12_FILE}", "--storepass", "env:LUNEPACK_P12_PASSWORD",
        "--tsaurl", "https://timestamp.example.com", "--alg", "SHA-256", "{path}"]
```

On a Mac, `scripts/macos-sign-check.sh` walks the whole real path with your own identity and notary
account: signing, notarization, stapling, Gatekeeper, translocation and continuity (credentials are named
by environment variable; `--dry-run` shows what it would do without them).

### `lunepack feed add`

Adds a release, or more targets of it, to a channel's feed (`feed-<channel>.json`).

```
lunepack feed add --release-dir <RELEASE_DIR> --channel <CHANNEL> --version <VERSION> --sign <SIGN>
    [--rollout <ROLLOUT>] [--rollout-seed <ROLLOUT_SEED>] [--expires-after-days <N>]
    [--trust-release-dir] [--allow-older-previous] [--config <CONFIG>]
```

- The targets are every `<version>/<target>.manifest.json` in the directory. A release already in the
  feed keeps its existing target references byte for byte: a target whose manifest changed is an error,
  and new targets are added.
- `--rollout`: basis points of installs, 0 to 10000. Without it an existing release keeps its rollout.
  `--rollout-seed`: 64 lowercase hex characters (default: the release's existing seed, else
  `SHA-256("lunepack-rollout-v1" 0x00 app_id 0x00 version)`).
- `--expires-after-days`: the feed's lifetime (default 90).
- The previous feed is read with its signatures checked and its time checks skipped, so an expired feed
  can be extended. If it does not verify under `keys.json`, the command stops and says so; it never
  reads an unverified feed and never deletes one (see Revoking a release key).
- The root walk, `keys.json` and the previous feed are then checked against the state file (see The
  publisher state file); `--trust-release-dir` and `--allow-older-previous` are its overrides.
- `seq` is `max(previous seq + 1, now in milliseconds)`. Releases are sorted by version precedence.
- Before the feed is placed, the new feed is verified, and so is every release it lists: each manifest
  under the key set and each pack in full (size, SHA-256, every frame decoded). This is slower on a
  feed with many releases and is deliberate.

### `lunepack feed refresh`

Re-signs a channel's feed with a new `seq`, `issued` and `expires`; the releases stay.

```
lunepack feed refresh --release-dir <RELEASE_DIR> --channel <CHANNEL> --sign <SIGN>
    [--expires-after-days <N>] [--drop <DROP>]... [--trust-release-dir] [--allow-older-previous]
    [--config <CONFIG>]
```

- `--drop <version>`: removes that release from the feed (repeatable). The text must equal a release of
  the verified previous feed, or the command exits 1. A feed with no releases left is valid. The release's
  files stay in the directory (`verify` lists their manifests as `unreferenced`).
- The same reads and the same full verification as `feed add`.

### `lunepack verify`

```
lunepack verify <DIR> [--at <AT>] [--config <CONFIG>]
```

Checks a directory the way a client does, in the client's order: the root walk (`root-<k>.json` from the
config's root), `keys.json`, every `feed-*.json` (the channel comes from the file name; a name that is
not a channel is an error), and for every release and target the manifest through the feed's reference,
the pack against the manifest's size and SHA-256, and every frame through the decoder. A manifest no feed
references is listed as `unreferenced` and does not change the exit status. One line per document is
printed; the exit status is 0 only if every check held. `--at` checks at that Unix time (expiry and key
windows) instead of the system clock.

### `lunepack inspect`

```
lunepack inspect <DIR> [--at <AT>] [--channel <CHANNEL>] [--version <VERSION>] [--target <TARGET>]
    [--entries] [--config <CONFIG>]
```

Runs the same verification as `verify` first and shows nothing if it fails. Then it prints a summary:
the key set (version, threshold, key ids, windows), each feed (seq, issued, expires, releases and
targets, rollout) and each manifest (entry counts, input and pack bytes, files per codec, ratio).
`--channel`, `--version` and `--target` narrow the output. `--entries` lists every entry: path, type,
size, exec, codec and frame length. It reads the config for the root only and never resolves a signer.

### `lunepack setup`

```
lunepack setup <DIR> --version <VERSION> --target <TARGET> [--out <FILE>] [--zip] [--at <AT>]
    [--config <CONFIG>]
```

Builds a Linux or Windows setup file (FORMAT.md 14; a `macos-*` target gets an installer `.dmg` or a `.zip` instead, below): the release's own runtime, then `keys.json`, the manifest
and the pack of `<VERSION>` for `<TARGET>`, then the trailer naming them and the root the release's
update configuration trusts. Run, the file installs exactly that version with no network, with the
window or `--silent` (RUNTIME.md, "Setup files").

Before anything is written it checks the release the way the runtime will: the root walk and
`keys.json` from the config's root, the manifest with no feed (release keys valid at the reader's
time), the pack against the manifest, then the update configuration and the runtime read out of the
pack through their signed frames. The release must have been packed with `[update]` and `--runtime`
(and `--ui` for a window). The written bytes are then parsed back and verified as the runtime
parses them, so `keys.json` must be signed under the root the update configuration names.

`<VERSION>` is the text as written in the release (canonical). The `linux-*`, `windows-*` and `macos-*`
targets are accepted in this release. The file goes to `--out`, or to
`<app_id>-<VERSION>-<TARGET>-setup` (with `.exe` for a `windows-*` target) in the current directory;
an existing file is not replaced. On a Unix host it is made executable (mode 0755). The output depends on the release directory only: two runs give
the same bytes. `--at` verifies at that Unix time instead of the system clock. A setup file stops
installing when its key set expires or its release keys' windows end: build it from a current
release.

**macOS (M8-D7, M8-D9).** A `macos-*` release has no setup file. `setup` writes one of two things, by the
same checks as above, taking every file out of the pack through its signed frame:

- **The installer `.dmg`** (default; a macOS host only, because it runs the system's `hdiutil`): an
  LZMA-compressed APFS disk image (`hdiutil create -format ULMO -fs APFS`, no Spotlight index, verified with
  `hdiutil verify` before it is placed; the volume is named after `install.name`, cut to 27 characters)
  that holds exactly one app, `Install <name>.app` (the bundle's own name rule, FORMAT.md 13.4, applies),
  built from the release's `lunepack-ui` as its main executable, its `lunepack-runtime`, a generated
  `Info.plist`, the release's `[macos] icon` when there is one, and the payload file
  `Contents/Resources/lunepack-setup.payload` (FORMAT.md 14.4). The release must have been packed with `--ui`:
  the installer's executable is the release's UI, so a release without one is refused, naming `--zip`.
  Opening the app shows the install window; `lunepack-runtime` inside it also installs with `--silent`
  (RUNTIME.md, "macOS"). The default name is `<app_id>-<VERSION>-<TARGET>.dmg`; `--out` must end in
  `.dmg`. With `[codesign.macos]` in the config the installer app is signed (its items inner to outer,
  then the app), notarized and stapled when the section has `notarize` and `staple`, and only then is the
  image built, signed, notarized and stapled ("Code signing"); without the section neither is signed.
  `hdiutil` decides the image's bytes, so two runs need not give the same image.
- **The `.zip`** (`--zip`; any host, no image tool): the bundle `<bundle name>.app` exactly as released, with
  every file's data and exec bit and every symlink as the manifest has them. It is written by lunepack's own
  writer over `flate2` (deflate, level 9 when that is smaller, else stored; names in UTF-8; times fixed at
  1980-01-01; Unix modes in the attributes; no ZIP64, so at most 65,535 entries and 4 GiB), so two runs give
  the same bytes, and `ditto -x -k`, `unzip` and Finder extract it to the same tree (a code-signed bundle
  still verifies). The default name is `<app_id>-<VERSION>-<TARGET>.zip`. A bundle dragged out of it has no
  install record: the first update check in `~/Applications` or `/Applications` adopts it after proving it
  equal to its release (RUNTIME.md, "macOS"); anywhere else it is a development run. `--zip` is refused for
  a Linux or Windows target.

## The release directory

```
<dir>/
  root-2.json                 # only after a root rotation
  keys.json
  feed-stable.json            # one per channel
  1.4.0/
    windows-x86_64.manifest.json
    windows-x86_64.pack
    linux-x86_64.manifest.json
    linux-x86_64.pack
```

Upload with any tool to any static host (D20; `lunepack publish` comes after v1). Order matters,
because a client that fetches a document must be able to fetch everything it points to:

1. packs (`<ver>/<target>.pack`);
2. manifests (`<ver>/<target>.manifest.json`);
3. `root-<k>.json` and `keys.json` (a feed signed by a new key needs the key set that lists it);
4. feeds (`feed-<channel>.json`) last. A feed is what makes a release visible.

Files already uploaded under a version are never changed: a manifest and a pack are never
overwritten by `pack`. To roll back a release, publish a feed without it.

## Revoking a release key

Revocation is a new `keys.json` without the key (FORMAT section 6). `lunepack` never reads a feed whose
signatures it cannot verify, so a feed signed by a removed key cannot be repaired in place. Revoke in
two moves (M3-R1-D1); nothing is uploaded between them, so the extra minutes the old key spends in the
local key set expose nothing.

1. Add the new key and keep the old one: `keys set` listing both. Sign with the new key:
   `pack` any new release, `feed add` it, and `feed refresh --sign <new>` (the previous feed still
   verifies, since the old key is listed). A release whose manifest only the old key signed cannot be
   carried: re-pack it as a new version, or drop it with `feed refresh --drop <version>`.
2. `keys set` listing only the new key. Then upload `keys.json` and the feeds (see the upload order).

`keys set` and `keys rotate-root` enforce this. If a feed, or a manifest it lists, would stop verifying
under the new key set, the command exits 1 and places nothing; stderr names each failing feed and each
`<version>/<target>`, and says: refresh the feed with a key you keep before removing this one, and drop
releases whose manifests only removed keys signed (`feed refresh --drop <version>`). No command leaves
a directory that `verify` would reject unless asked to with `--allow-unverifiable-feeds`, and then it
names each such feed.

Fallback, for an operator who already removed the key: `feed add` and `feed refresh` stop with
"the existing feed-<channel>.json does not verify". Delete that feed file yourself and run `feed add`
to start the channel again, or restore the previous `keys.json` and revoke in two moves. A restarted
channel loses its rollouts, and its `seq` restarts from the writer clock's milliseconds. Clients keep
the highest `seq` they have seen (FORMAT 11.2), so publish only with a clock later than the old feed's
`issued` time, or clients ignore the new feed as a replay.

Known limitation (owner: the milestone that revisits the threat model): a leaked release key that meets
the threshold can sign a feed with `seq` = 2^53-1. Clients then keep that floor, and the writer rule
"`seq` strictly increases" stops `feed refresh` on that channel. Workaround: publish under a new
channel name.

## Determinism (C2)

For the same input tree, version, target, config, key set and signers, and the same
`SOURCE_DATE_EPOCH`, the pack and the manifest are byte-identical: for any `--jobs`, for any
`--memory-budget-mib`, on a re-run, in a different temporary directory. This holds because file order,
codec choice, encoder settings (the equivalent of liblzma's 9e, a dictionary derived from each file's
length) and the layout are fixed, and Ed25519 signatures are deterministic. Not covered:

- documents written without `SOURCE_DATE_EPOCH` carry the wall-clock time (`issued`, `seq`);
- a command signer may not sign deterministically (that is the command's property);
- the `exec` bit and symlinks come from the file system, so a Windows and a Unix checkout of the same
  files differ;
- a release signed through `[codesign.<os>]` is as deterministic as the signing tool: a timestamped
  signature or a notarization ticket differs from run to run. A pack with no `[codesign.*]` section for its
  OS is byte-identical to one from before M9;
- identical bytes on different CPU architectures (arm64 against x86-64) are asserted by known-answer
  tests, which first run on all three operating systems at the first push.

## Memory limit

The pack is built in memory (M3-D8): peak use is about the compressed pack plus the encoder budget
(`--memory-budget-mib`). An encoder at the highest preset holds about ten times its dictionary (at most
16 MiB), and each file in flight is counted at its input, up to twice its size for the best candidate so
far and the running candidate's output (an x86 executable's `bcj2` candidate is counted at up to five
times its size more, for its split streams), so very large single files and multi-gigabyte apps need
that much free RAM until a streaming pack writer exists. Raise
`--jobs` only if the budget allows it; lower the budget to trade speed for memory.
