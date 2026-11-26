# lunepack CLI

`lunepack` packages an app's build output into a signed release directory that any static host can
serve, and checks such a directory the way a client does. The directory layout, the documents and
the signatures are defined in [`docs/FORMAT.md`](FORMAT.md); the decisions behind the tool are
M3-D1 to M3-D13 and M3-R1-D1 of the project's internal decision log (not part of this repository; the
rules are stated here); what it defends against is in
the packager section of [`docs/THREAT-MODEL.md`](THREAT-MODEL.md).

Walk-throughs with real output: [`docs/GETTING-STARTED.md`](GETTING-STARTED.md) (a Rust app),
[`docs/INTEGRATION.md`](INTEGRATION.md) (an app in any language) and [`docs/KEY-CEREMONY.md`](KEY-CEREMONY.md)
(making, keeping, rotating and revoking the signing keys).

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
file is stored when no candidate is smaller than the file. An app in any language learns that an update
exists and triggers it from inside the app through the runtime's command line (`docs/RUNTIME.md`;
`docs/INTEGRATION.md` walks through it with a .NET app).

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

[install.windows]            # optional: `entry` and `icon` only, for the targets of that OS (also
                             # [install.linux] and [install.macos]); see "`[install.<os>]` and `pack --channel`"
entry = "bin/hello.exe"

[publish]                    # optional: where and how `lunepack publish` ships releases; see "Publishing"
prefix = "hello"
store = "r2"
account_id_env = "EXAMPLE_R2_ACCOUNT_ID"
access_key_env = "EXAMPLE_STORE_ACCESS_KEY"
secret_key_env = "EXAMPLE_STORE_SECRET_KEY"
public_bucket = "example-updates"
private_bucket = "example-updates-private"

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
- `env:<VAR>`: a PKCS#8 PEM key held in the environment variable `VAR`. This is how lunepack's own
  release workflow hands over its key (`prebuilt sign`); the variable is visible to the process that
  holds it and to its children, so set it only on the command that needs it.

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
system clock. `lunepack publish push`, `refresh` and `init` refuse it ("Publishing"). `verify` and `inspect`
use the system clock or `--at <unix>`; they ignore
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
(the key id, SHA-256 of the public key) on stdout, nothing else; its own message `wrote the private key to
<path>` goes to stderr. The directory of `<PATH>` must exist: the command does not create it.

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
- `--expires`: when the key set expires (Unix time); none by default, and not carried over from the
  previous key set: a `keys set` without it writes a key set with no expiry (its `change:` line says
  `expires <time> -> none`).
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
in the release directory, with a delta file `<version>/<target>.from-<from>.delta` per earlier release
it patches from ("Deltas" below).

```
lunepack pack --input <INPUT> --version <VERSION> --target <TARGET> --release-dir <RELEASE_DIR>
    --sign <SIGN> [--app-id <APP_ID>] [--jobs <JOBS>] [--memory-budget-mib <MEMORY_BUDGET_MIB>]
    [--deltas <N>] [--channel <CHANNEL>] [--runtime <RUNTIME>] [--ui <UI>] [--stub <STUB>]
    [--service <SERVICE>] [--require-pinned] [--config <CONFIG>]

lunepack pack --input <INPUT> --version <VERSION> --target <macos-TARGET> --runtime <RUNTIME>
    [--ui <UI>] --assemble <DIR> [--require-pinned] [--config <CONFIG>]
```

- `--version`: SemVer 2.0.0, used verbatim as the directory name. A directory of equal precedence with
  other text (they differ only in build metadata) is refused.
- `--target`: one of `windows-x86_64`, `windows-aarch64`, `macos-x86_64`, `macos-aarch64`,
  `macos-universal`, `linux-x86_64`, `linux-aarch64`.
- `--jobs`: encoder threads (default: the available parallelism). The output does not depend on it.
- `--memory-budget-mib`: memory budget of the encoders (default 2048). A file that needs more than the
  whole budget is encoded alone; a delta patch candidate that needs more is not encoded at all (below).
- `--deltas <N>`: how many earlier releases to patch from, per feed (default 3, `0` for none, at most
  16); see "Deltas".
- `--app-id`: when given, it must equal the config's.
- `--channel <c>`: the channel the packed tree follows, written into the update config instead of
  `[update] channel`. It needs `[update]`, and `c` must be one of `[publish] channels` ("Publishing").
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
inside its window; the signers reach the threshold; the manifest, the pack and the delta files do not
exist yet; the target is valid for this host (below).

The stages, in order (C2): (1) assemble: copy the input into a temporary directory (removed on success
and on every error); (2) code-sign: the OS sign stage, the developer's argv templates run over the items of the sign plan,
inner to outer, when the config has a `[codesign.<os>]` section for the target's OS ("Code signing"),
nothing otherwise; (3) hash every file; (4) pack: choose the smallest codec per file, round-trip it through the decoder a client uses,
and lay the frames out; then the delta patches ("Deltas"); (5) sign the manifest. `pack` then verifies
its own output the way a client does (a throwaway feed signed by the same signers, `verify_manifest`,
the pack against the manifest's size and SHA-256, every frame decoded, every delta file and patch
against the manifest) and only then writes the pack, the delta files and, last, the manifest. None is
ever overwritten. Stdout has one line per stage and the totals: files, input bytes, pack bytes, files
per codec and the candidates that were dropped, with reasons, then the delta report. A signed manifest
over the format's 64 MiB cap is an error that names `--deltas`.

#### Deltas (M12, FORMAT.md 9.3)

An update can download a small patch against the file the user already has instead of the file's
frame. `pack` writes, for each earlier release it patches from (a *base*), one delta file
`<version>/<target>.from-<base>.delta` holding the patches back to back, and lists it in the signed
manifest's `deltas`; installers carry the manifest unchanged and no delta file.

Bases (M12-D3). The candidates are the version directories of the release directory with lower
precedence than `--version` that hold `<target>.manifest.json`. Every `feed-<channel>.json` is
verified under `keys.json`, without the time checks `pack` skips on every document it reads (expiry
and key windows: an expired feed still names its releases);
a feed that does not verify is ignored with a report line. With at least one usable feed, the bases
are the union of each feed's `--deltas` highest candidates it lists for the target, so a stable user
still gets a patch after several betas; with no usable feed, the `--deltas` highest candidates. At
most the 16 highest are kept. A base's manifest is verified the way `verify` does (through the feed's
entry; with no feed, the way `setup` does, release keys valid at the writer's time) and its pack must
match the manifest's size and SHA-256; a base that fails either, or one of whose files does not decode
from its pack, is skipped with a report line naming its version.

Patches (M12-D4). A file gets a patch from a base when it has at least one byte, the base has a file
at the same path with at least one byte and another SHA-256, and the window (`base size + file size`
rounded up to 4096) is at most 128 MiB, so files of about 64 MiB and up get none. A renamed file gets
none. The candidates are `lzma2`, plus `bcj-x86+lzma2` or `bcj-arm64+lzma2` (both for a fat Mach-O
with both) for code of that architecture, each encoded at the frame settings and round-tripped
through the client's own patch decoder; the shortest is written only if it is at least 10% shorter
than the file's frame. A delta with no patch is not written. Every changed file without a patch gets
one report line, `no-patch: <path> from <base>: <reason>`, the reason one of `window` (over 128 MiB),
`memory` (with the estimate and the budget in MiB), `not-smaller` (the 10% rule) or `failed` (the
encode or the round trip failed; the candidate is also listed as `dropped`).

Time and memory (M12-D7). Each candidate is one job of the encoders' memory gate, estimated as the
encoder's memory for its window plus the base and the file; at a 64 MiB window that is about 0.85 GB
(`lzma2`) and 0.9 GB (BCJ), at the 128 MiB cap about 1.7 to 1.8 GB. A candidate whose estimate is over
the whole `--memory-budget-mib` is not run: the file keeps its frame and its report line says
`memory`. So the delta files depend on the budget as well as on the tree, the keys, the clock, the
earlier releases and the feeds in the directory; given those, the output is byte for byte the same
for any `--jobs`. A large changed file costs about 20 s per candidate at a 64 MiB window (up to
about a minute at the cap), with up to two candidates per base and three bases by default; lower
`--deltas` to pack faster. Measured on real 30 to 32 MB executables with one base and the defaults, the whole
`pack` took 41 to 68 s and peaked at about 1.8 GB of process memory (D8 of the project's internal decision log).

Upload order: the pack and the delta files first, then the manifest, then the feed (`feed add`), so a
client never sees a manifest whose files are missing.

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
- Each lunepack binary given (`--runtime`, `--ui`, `--stub`, `--service`) is hashed as read, before the
  stub is stamped and before code signing, and stdout gets one line per binary: `binary: <flag> is a
  pinned release binary (<kind> <version> <target>)` or `binary: <flag> is a local build`. A binary is
  pinned only when this CLI is in the state `pinned` (`lunepack prebuilt list` below) and its list has a
  row of the binary's kind for exactly the pack's `--target` with the binary's size and SHA-256: there is
  no fallback between `macos-universal` and `macos-x86_64` or `macos-aarch64`, and `--stub` is the kind
  `stub-console` when `install.terminal` is true and `stub` otherwise. The pack's bytes do not depend on
  the classification. With `--require-pinned` a local build is an error that names the flag, the file and
  the command that downloads the pinned binaries, `lunepack prebuilt fetch --target <TARGET> --out <DIR>`;
  nothing is written. In the state `inconsistent` stderr gets one warning line and every binary is a
  local build.

Reserved names, each an error before anything is written:

- a file or directory named `lunepack-update.json` (any case) at any depth of the input, so nothing
  can shadow the root configuration when an executable looks for the nearest one above itself;
- a file named `lunepack-runtime` or `lunepack-runtime.exe` (any case) in the entry's directory, or a
  file named `lunepack-ui` or `lunepack-ui.exe` there, with or without `--ui`: the runtime starts a
  UI from its own directory, so the name is never left to an app file.
- a file named `lunepack-NOTICES.txt` (any case) in the entry's directory (`Contents/Resources` for
  `macos-*`), where `pack` places the third-party notices (below).

The feed (`[update] feed`) must pass the feed rule of FORMAT.md 13.3, which `pack` checks with the same
function a client runs before its first request: `https://` with a lowercase DNS name or an IPv4
address, `file:///`, or `http://` to a loopback IP literal (`127.x.y.z` or `[::1]`) only; no user
information, query, fragment, percent-encoding, uppercase or non-canonical form; a trailing `/` is
added when missing. `http://` to any other host, `localhost` included, is refused: the error names
`[update] feed` and the rule that failed and never prints the feed.

Third-party notices (M13-D11): wherever `pack` places the runtime it also places `lunepack-NOTICES.txt`, a
text file (not executable) beside the runtime, in the entry's directory, or in `Contents/Resources` for
`macos-*`. It names every Rust package linked into the release binaries (`lunepack-runtime`,
`lunepack-service`, `lunepack-stub`, `lunepack-ui` and `lunepack`) with its licence and licence texts, and
holds the bundled font's licence and LuneUI's own notices; an app that ships the runtime thereby ships the
notices the binaries' licences ask for. The CLI carries the file, `crates/lunepack-cli/THIRD-PARTY-NOTICES.txt`,
which `cargo run -p xtask -- notices` generates from `cargo metadata` and the gate checks (`notices --check`
fails when it is stale, or when a package has no licence expression, a licence outside the allowlist or no
licence text). The notices are bytes of the CLI itself, so the same CLI gives the same pack (C2). A pack
without a runtime has no notices file, and the app's own licence notices stay the app's to ship.

Determinism (C2) covers the runtime too: the same inputs, runtime bytes, keys and `SOURCE_DATE_EPOCH`
give a byte-identical configuration, pack and manifest. `verify` accepts the result; `inspect` lists
the two files like any others.

Building the runtime: `scripts/build-runtime.sh <linux-x86_64|linux-aarch64>` runs the static musl
build (the target must be installed with `rustup target add`; `--print-command` shows the command and
runs nothing). `pack` never builds a runtime from source and never touches the network: a runtime
you built yourself comes from these scripts in a checkout and is passed by path, and the runtime,
UI, service and stubs of a lunepack release are downloaded, checked against the pins of this CLI,
with `lunepack prebuilt fetch` (below).

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

**Linux for all users (M11-D9).** The same setup file of a `linux-*` release packed with `--service` also installs for
all users: its window's "Install for all users" goes through `pkexec`, or shows the `sudo '<file>' --all-users`
command to run in a terminal, and a run as root with `--all-users` installs headless (RUNTIME.md, "Per-machine
installs (Linux and macOS, M11)"). The file carries **no anchor**: the `pkexec` prompt names a path, not a
publisher, so there is nothing a digest in the file could tell the administrator; the root side copies the payload
out of its own executed image and verifies it under the trailer's root (THREAT-MODEL, "Linux and macOS
per-machine"). Distribute the file from the publisher's own channel and publish its checksum.

### macOS targets (M8)

A `macos-*` pack with `[update]` packs an app bundle (`<Name>.app`'s contents) and adds files inside it,
each written before hashing so the signed manifest covers them (FORMAT.md 13, 17):

- The input must hold `Contents/Info.plist` as a regular file, and `install.entry` must be
  `Contents/MacOS/<file>` (an executable regular file). The error names `Contents/Info.plist` or
  `[install] entry`, never the value.
- The runtime is placed beside the entry, `Contents/MacOS/lunepack-runtime` (marked executable), and the
  update configuration at `Contents/Resources/lunepack-update.json`, with the third-party notices
  (`lunepack-NOTICES.txt`, not executable) beside it.
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
  names `lunepack-update.json` (at any depth), `lunepack-runtime` and `lunepack-ui` in
  `Contents/MacOS`, and `Contents/Resources/lunepack-NOTICES.txt`. Comparison ignores ASCII case.
- Symlinks are packed as links, unchanged, and must satisfy FORMAT 10.2: a target stays inside the
  bundle, may pass through other links inside it (a framework's `Versions/Current` → `A` and `Foo` →
  `Versions/Current/Foo` pack as they are), and follows at most 8 of them. Exec bits come from the
  Unix mode.
- The installed bundle's name is `install.name` when it can be a file name: 1 to 200 UTF-8 bytes, no `/`,
  `:` or control character, no leading `.` (FORMAT.md 13.4). Otherwise it is the app id. `pack` still
  packs, and warns on stderr, naming the rule and never the name.

**Files in `Contents/MacOS` (M13-D12).** When the bundle is, or will be, code-signed (it holds
`Contents/_CodeSignature`, or the config has a `[codesign.macos]` section), `pack` refuses it if any regular
file under a `Contents/MacOS` directory, of the bundle or of a nested bundle, is not a Mach-O file, except
the bundle's main executable (`install.entry`) and, in a signed bundle, the files `pack` itself places. The
error names up to ten of the paths. The reason: `codesign` keeps the signature of a file that is not
Mach-O in an extended attribute of that file, and a pack carries no extended attributes (FORMAT.md 8.1), so
the bundle that is installed from the pack would fail `codesign --verify --deep --strict`. Move such files
(the managed `.dll` files of a .NET app, scripts, data) under `Contents/Resources`, and let the host find
them there; `examples/dotnet` does this with a host whose app path points at `Contents/Resources/app`. The
rule is one instance of a general one: a signature must not depend on anything the pack does not carry
(the extended attributes of a file are the case found). An unsigned bundle with no
`[codesign.macos]` section is packed as before.

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
| `sign_installer` | optional, default `sign`: what `setup` signs (`Setup.exe`, the installer app's items and the app, the `.dmg`, the all-users `.pkg`) |
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
signs, notarizes and staples the `.dmg`: two notarizations. A release with the update service has a third
object, the all-users `.pkg` (below): it is built, signed, notarized and stapled first, then embedded in the
installer app, so the app's own seal and notarization cover it. `sign_installer` signs the `.pkg` in place
(`productsign` writes a second file, so call it from a small script that signs to a new file and renames it
over `{path}`), and `notarize` and `staple` take the package as `{path}`, `{bundle}` and `{zip}` alike, as for
the image. `setup` checks that the `xar` table of contents of the package holds a signature after
`sign_installer`; `pkgutil --check-signature` is the real verification. The `.zip` installer holds the bundle as
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
the pack against the manifest's size and SHA-256, and every frame through the decoder; then every delta
file a verified manifest lists: its size and SHA-256 and every patch's SHA-256, and, when the base
release is among the verified manifests, every patch decoded against the base's file read back from the
base's pack (the base file must be that release's file at the path, of the patch's base size and
SHA-256). A delta whose base is not in the directory is reported as not round-tripped, which is not an
error; a missing or changed delta file is. A manifest no feed
references is listed as `unreferenced` and does not change the exit status. One line per document is
printed; the exit status is 0 only if every check held. `--at` checks at that Unix time (expiry and key
windows) instead of the system clock.

The trust chain is read by the same code a client runs (the core's root walk, FORMAT.md 5.2 and 11.1), for
`verify` and for every command that reads a release directory (`inspect`, `pack`, `feed`, `keys`,
`setup`): for the same compiled-in root, clock and directory, `verify` accepts exactly when a client
with no stored state accepts. So the walk takes at most 1024 root rotations (a directory with more
`root-<k>.json` files than that is read only up to the 1024th, and a `keys.json` signed under a later
root does not verify), the app id of the root the walk ends on must be the config's, and a `root-<k>.json`
that does not verify fails with its file name. The commands that write a root or a key set check what
they built through the same walk before they place it.

### `lunepack inspect`

```
lunepack inspect <DIR> [--at <AT>] [--channel <CHANNEL>] [--version <VERSION>] [--target <TARGET>]
    [--entries] [--config <CONFIG>]
```

Runs the same verification as `verify` first and shows nothing if it fails. Then it prints a summary:
the key set (version, threshold, key ids, windows), each feed (seq, issued, expires, releases and
targets, rollout) and each manifest (entry counts, input and pack bytes, files per codec, ratio, and
per delta: the base, the delta file's size, the patch count and the patch bytes against the bytes of
the frames they replace).
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

**macOS (M8-D7, M8-D9, M11-D8).** A `macos-*` release has no setup file. `setup` writes one of two things (three
with the service: the `.pkg` below is written beside the `.dmg`), by the same checks as above, taking every file out
of the pack through its signed frame:

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
- **The all-users `.pkg`** (M11-D8; with the `.dmg`, for a release packed with `--service`, which holds
  `Contents/MacOS/lunepack-service` beside the entry): a product archive built with the system's `pkgbuild` and
  `productbuild` (a macOS host only, as the image is), named like the image with the extension `.pkg`
  (`<app_id>-<VERSION>-<TARGET>.pkg`, beside `--out`; an existing file is not replaced, and nothing is written
  when it exists). Its payload is the release's `lunepack-runtime` and the payload file of FORMAT.md 14.4
  (the runtime and the key set, manifest and pack through their signed frames), installed below
  `/Library/Application Support/lunepack/.installer/<app id>/`: every folder above `.installer` is recorded as
  root 0755, `.installer` and the app's folder as root 0700, the runtime 0700 and the payload 0600, so nobody but
  root can read or change them between Installer's copy and the script. The package has one script, a
  `postinstall` whose only command is `exec "<that folder>/lunepack-runtime" machine-install --pkg`: it reads no
  argument and no environment variable. Its distribution (identifier `<app id, with _ as ->.lunepack-machine`,
  the installer's title the app's display name, macOS 10.15 or later) allows the local system domain only, no
  per-user or anywhere install. The same file is embedded as `Contents/Resources/lunepack-all-users.pkg` in the
  installer app, so that the installer window's "For all users" can hand over to Installer. A release
  without the service gets neither, and `--zip` never builds one.
- **The `.zip`** (`--zip`; any host, no image tool): the bundle `<bundle name>.app` exactly as released, with
  every file's data and exec bit and every symlink as the manifest has them. It is written by lunepack's own
  writer over `flate2` (deflate, level 9 when that is smaller, else stored; names in UTF-8; times fixed at
  1980-01-01; Unix modes in the attributes; no ZIP64, so at most 65,535 entries and 4 GiB), so two runs give
  the same bytes, and `ditto -x -k`, `unzip` and Finder extract it to the same tree (a code-signed bundle
  still verifies). The default name is `<app_id>-<VERSION>-<TARGET>.zip`. A bundle dragged out of it has no
  install record: the first update check in `~/Applications` or `/Applications` adopts it after proving it
  equal to its release (RUNTIME.md, "macOS"); anywhere else it is a development run. `--zip` is refused for
  a Linux or Windows target.

### `lunepack prebuilt list`

Shows the project's key sets compiled into this CLI and the prebuilt lunepack binaries it pins: the
runtime, UI, service and stubs of the lunepack release of this CLI's own version.

```
lunepack prebuilt list [--target <TARGET>] [--json]
```

The CLI carries three things, all part of its source and of its crates.io package: the project's key
sets (public keys only; `src/project_key.rs`, oldest first, the last one current), the pin table
`prebuilt.json` and its signed envelope `prebuilt.sig.json` (FORMAT.md 21). At every use (`pack`,
`prebuilt list`) it decides one state:

| State | Meaning |
| --- | --- |
| `no-key` | No project key set: nothing is pinned. A CLI built before the project's key ceremony is in this state. |
| `none` | A key set, and both list files are empty: nothing is pinned. |
| `pinned` | The envelope verifies under the current key set, its payload is byte for byte the table, the list is of this CLI's version and is not a rehearsal list: its rows are pinned. |
| `rehearsal` | As `pinned`, but the list is a rehearsal list: shown, nothing is pinned. |
| `other-version` | As `pinned`, but the list is of another version: shown, nothing is pinned. |
| `inconsistent` | Anything else: one list file without the other, a list without a key set, a table that is not the envelope's payload, an envelope that does not verify under the current key set (also one that verifies only under an earlier, retired set), a parse error, or a row whose `size` is above what `pack` reads for its kind. Nothing is pinned. |

No flag, environment variable or file adds to or replaces the compiled-in key sets for these checks.

The text output is a `state:` line (with a `reason:` line in the state `inconsistent`), one `key set
<n>: threshold <t>, current|retired` line per key set with a `key: <public key> id <key id>` line per
key (or `key sets: none (no project key has been published)`), and, for a list, a `list:` line (version,
source commit, rehearsal) and one `binary:` line per row: kind, target, size, SHA-256 and the release
asset's name, `lunepack-<kind>-<version>-<target>` (plus `.exe` for a `windows-*` target), computed and
never read from the table. `--target` shows only that target's rows. `--json` prints one object with
the members `state`, `reason` (null unless `inconsistent`), `roots` (per key set: `version`,
`threshold`, `current` and `keys`, each with `public` and `id`), `list` (null, or `version`,
`source_commit` and `rehearsal`) and `binaries` (per row: `kind`, `target`, `size`, `sha256`, `asset`).
In the state `inconsistent` the command prints its report, then exits 1 with the reason on stderr.

### The project's list of prebuilt binaries: `prebuilt check`, `sign` and `verify`

These three commands handle the signed list of a lunepack release's prebuilt binaries (FORMAT.md 21)
that the release workflow makes and `prebuilt list` and `pack` read. They are for the maintainers of
lunepack and for anyone who wants to check a release by hand. None of them needs the network.

**Which key set.** A `sign` or `verify` runs under the current built-in key set of this CLI
(`prebuilt list` shows it) unless the command line names another: `--trusted-key <hex>` (a public key
as 64 lowercase hex characters; give it 1 to 16 times, with `--threshold <n>` when more than one) on
`sign` and `verify`, or `--root-version <n>` (an earlier built-in set) on `verify` only. The two never
go together. These flags are never read from the environment or a config, and every result says which
set it held under: `verified under built-in key set 2, the current one`, `verified under built-in key
set 1, which is retired`, or `verified under a key given on the command line, not a built-in one`. A
given set is built by the same function as a built-in one, so the same rules apply (1 to 16 keys, none
twice, `1 <= threshold <= keys`). With no built-in key set and no `--trusted-key`, both commands refuse
with `this CLI has no project key built in`.

#### `lunepack prebuilt check`

```
lunepack prebuilt check --list <FILE> [--json]
```

Reads a list with this CLI's own parser and prints what it read; it exits 0 only when the list is
accepted. It reads nothing but the file: no key, no signature, no network. `--json` prints one object
with `version`, `source_commit`, `rehearsal` and `binaries` (per row `kind`, `target`, `size`,
`sha256` and `asset`, the computed release asset name), so a script that reads these values reads what
the enforcer read.

```
$ lunepack prebuilt check --list prebuilt-0.1.0.json
list: version 0.1.0, source commit 0123456789abcdef0123456789abcdef01234567, rehearsal false
binary: runtime linux-x86_64 size 13 sha256 7fc5036745ec73b6169495830cf3ef3b58127addf27fcc0d0b8fe87b4de5808c asset lunepack-runtime-0.1.0-linux-x86_64
binary: ui windows-x86_64 size 8 sha256 62ea1f22117e10e5af59aba1dd236f5878e3626bc3767b5ac202c3da8dafe718 asset lunepack-ui-0.1.0-windows-x86_64.exe
```

A list the parser refuses prints nothing on stdout and `error: the list is not accepted: <rule>` on
stderr (exit 1): for example a document over 64 KiB, a member given twice, `rehearsal` missing or not
a boolean, or trailing data.

#### `lunepack prebuilt sign`

```
lunepack prebuilt sign --list <FILE> --out <FILE> --sign <SPEC>... [--trusted-key <HEX>... [--threshold <N>]]
```

Signs the exact bytes of the list (no re-serialisation) and writes the envelope
(`prebuilt-<version>.sig.json`). The list must pass `prebuilt check` and be of this CLI's own version.
Signers are the specs of "Signer specs" above, resolved with the global `--config` path; `file:` and
`env:` work when that config does not exist. No key is printed, logged, written to a file or passed as
an argument, and no new way to load a key exists.

Before anything is written the envelope is verified under the key set. When it does not verify (a
signer that is not one of the keys, too few signers for the threshold) nothing is written and the error
names the key ids the set expects and the ids that signed (key ids are public), so a secret that holds
the wrong key fails closed. The output file is created with `create_new`: an existing file is an error.

In the examples, `$PUBLIC` is the `public:` value `keys gen` printed for a throwaway key made for them;
the public key and its id are shown shortened (`...`) in the `key:` lines, they are 64 characters long.

```
$ lunepack prebuilt sign --list prebuilt-0.1.0.json --out prebuilt-0.1.0.sig.json \
    --sign file:./release-signer.lpk --trusted-key "$PUBLIC"
envelope written: prebuilt-0.1.0.sig.json
verified under a key given on the command line, not a built-in one
key set: threshold 1 of 1
  key: 930ca1c4...48714 id dbb52593...92d22
```

`env:<VAR>` is how lunepack's own release workflow hands its project key to this command
(`--sign env:LUNEPACK_PROJECT_KEY`). The variable is visible to the process that holds it and to its
children, so it is set on the one step that needs it and nowhere else.

#### `lunepack prebuilt verify`

```
lunepack prebuilt verify --list <FILE> --sig <FILE> [--root-version <N> | --trusted-key <HEX>... [--threshold <N>]]
                         [--dir <DIR> [--all]] [--allow-rehearsal] [--json]
```

Checks a release's list against its envelope: the envelope must verify under the key set, and the
decoded payload must equal the `--list` file byte for byte. A list whose `rehearsal` is `true` is a
rehearsal of the release process: it fails with `rehearsal list` unless `--allow-rehearsal` is given,
and is labelled `rehearsal true` either way.

With `--dir`, the files in that directory (not its subdirectories) are checked against the rows: every
file that bears a row's asset name must have the row's size and SHA-256; a file named like a lunepack
binary of the list's version (`lunepack-<kind>-<version>-...`) that no row names is an error; no
matching file at all is an error; with `--all` every row's file must be present. A symbolic link or
another file that is not a regular file under a row's name is an error. Files are only read and hashed,
never run or parsed. The command exits 0 only when everything asked for passed; on any failure it
prints nothing on stdout and the reasons on stderr.

```
$ lunepack prebuilt verify --list prebuilt-0.1.0.json --sig prebuilt-0.1.0.sig.json \
    --trusted-key "$PUBLIC" --dir downloads --all
list: version 0.1.0, source commit 0123456789abcdef0123456789abcdef01234567, rehearsal false
binary: runtime linux-x86_64 size 13 sha256 7fc5036745ec73b6169495830cf3ef3b58127addf27fcc0d0b8fe87b4de5808c asset lunepack-runtime-0.1.0-linux-x86_64
binary: ui windows-x86_64 size 8 sha256 62ea1f22117e10e5af59aba1dd236f5878e3626bc3767b5ac202c3da8dafe718 asset lunepack-ui-0.1.0-windows-x86_64.exe
verified under a key given on the command line, not a built-in one
key set: threshold 1 of 1
  key: 930ca1c4...48714 id dbb52593...92d22
files: 2 checked, every row present
```

A file that differs from its row:

```
$ lunepack prebuilt verify --list prebuilt-0.1.0.json --sig prebuilt-0.1.0.sig.json \
    --trusted-key "$PUBLIC" --dir downloads
error: the files do not match the list:
  lunepack-ui-0.1.0-windows-x86_64.exe: 9 bytes, the list says 8
```

`--json` prints one object: the members of `prebuilt check --json`, `key_set` (`source`, `built-in` or
`command-line`; `version` and `current`, null for a given set; `retired`; `threshold`; `keys`, each
with `public` and `id`; and the `label` sentence above) and `files` (null, or `checked`, the asset
names that were checked, and `all`).

A pass proves that the holders of the key set signed this list and that the files are the ones it
names. It says nothing about how the files were built. Check a release with a CLI you obtained before
it or from crates.io, not with one downloaded together with the files.

### `lunepack prebuilt fetch`

```
lunepack prebuilt fetch --target <TARGET> --out <DIR> [--kind <KIND>]... [--base-url <URL>]
```

Downloads the prebuilt binaries this CLI pins for one target (`linux-x86_64`, `linux-aarch64`,
`windows-x86_64`, `macos-universal`, `macos-aarch64` or `macos-x86_64`), checks each against its pinned row and places it in `<DIR>`.
This is the only command that uses the network for them: `pack` never downloads anything, and
`pack --require-pinned` names this command when a binary is a local build.

- It needs the state `pinned` (`prebuilt list`). In every other state (`no-key`, `none`, `rehearsal`,
  `other-version`, `inconsistent`) it exits 1 with one line that names the state (and, for
  `inconsistent`, the reason), opens no connection and does not create `--out`. The rows come from the
  state and from nowhere else: never from a file or a list on the network. The state is decided before
  `--base-url` is looked at.
- Each file is requested as `<base><asset name>` (`lunepack-<kind>-<version>-<target>`, plus `.exe` for
  a Windows target). The default base is the GitHub release of this CLI's version,
  `https://github.com/lune-rs/lunepack/releases/download/v<version>/`. `--base-url` (ending in `/`, one
  is added when missing) follows the rule of an update feed: `https://`, `file:///`, or `http://` to a
  loopback address; anything else is refused before any request, without showing the URL. Redirects are
  followed up to the transport's limit.
- At most the pinned size plus one byte is read. A body of another size, or with another SHA-256, is
  refused with the asset's name and the expected and actual size or the two digests; the temporary file
  is removed and nothing is placed under the asset's name. A file that passed is placed by a rename
  from a temporary file in `<DIR>`, with mode 0755 on Unix. Nothing downloaded is run, parsed or
  unpacked.
- A file already in `<DIR>` under the asset's name with the pinned SHA-256 is left alone (`present`); one
  with another hash is replaced only after the new file has passed. A link or a directory under that
  name is an error.
- `--kind` (`runtime`, `ui`, `service`, `stub`, `stub-console`; repeatable) limits the files to those
  kinds; the default is every row of the target.

On success each file prints `fetched: <asset> (<size> bytes)` or `present: <asset>`, then a summary
line. In this CLI as built from the repository, where no project key has been published yet:

```
$ lunepack prebuilt fetch --target linux-x86_64 --out ./downloads
error: prebuilt fetch needs this CLI in the state pinned, it is in the state no-key: no project key is built in, so nothing is pinned
```

## Publishing: `lunepack publish`

`lunepack publish` is the standard way to put a release on a store and keep it there: it fills a
release directory from what is published, checks the store against it, uploads in the order a client
needs, trims old releases and keeps the feeds fresh. The recommended flow, with a CI example and the
rules for an agent, is in [`docs/PUBLISHING.md`](PUBLISHING.md). This section is the reference.

```
lunepack publish fetch   --release-dir <DIR> --version <VERSION>
lunepack publish push    --release-dir <DIR>... --version <VERSION> --sign <SIGN>...
    [--require-targets <T,T,...>] [--dry-run] [--store-dir <DIR>]
lunepack publish refresh --sign <SIGN>... [--if-expiring-within-days <N>] [--skip-if-unpublished]
    [--dry-run] [--store-dir <DIR>]
lunepack publish plan    [--version <VERSION>] [--store-dir <DIR>]
lunepack publish init    --release-dir <DIR> [--dry-run] [--store-dir <DIR>]
```

Every command also takes `--config <CONFIG>`. They need `[update]`, `[install]` and `[publish]` in the
config. Exit codes are the CLI's: 0, 1 (a command failed or refused), 2 (a usage error: a version that
is not SemVer or not usable as a folder name, a target id that is none, a missing required flag).

### `[publish]`

Names of environment variables, never their values. Unknown keys are errors.

```toml
[publish]
prefix = "hello"                         # one path segment: every object lives under <prefix>/
store = "r2"                             # "r2" or "s3"
account_id_env = "EXAMPLE_R2_ACCOUNT_ID" # r2 only: the variable that holds the account id
# endpoint_env = "EXAMPLE_S3_ENDPOINT"   # s3 only: the variable that holds the endpoint URL
# region = "us-east-1"                   # s3 only
access_key_env = "EXAMPLE_STORE_ACCESS_KEY"
secret_key_env = "EXAMPLE_STORE_SECRET_KEY"
public_bucket = "example-updates"        # what clients read: keys, roots, feeds, releases
private_bucket = "example-updates-private" # the state file and the pending-deletes record
keep = 10                                # releases kept per channel, 1..=100 (default 10)
deltas = 3                               # earlier releases `fetch` brings as delta bases, 0..=16 (default 3)
feed_days = 90                           # a feed's lifetime when push or refresh signs it, 1..=3650 (default 90)
channels = ["stable", "beta"]            # default: [update] channel alone
prerelease_channels = ["beta"]           # where a pre-release goes; a subset of channels; default: all of them
require_targets = ["linux-x86_64", "windows-x86_64", "macos-universal"]   # default: none
```

- `public_bucket` and `private_bucket` must differ (both 3 to 63 of `a-z`, `0-9`, `.` and `-`). The
  public read URL is `[update] feed`; the public bucket is what it serves.
- `store = "r2"` signs for Cloudflare R2 (region `auto`; the account id is 32 lowercase hex characters); `store = "s3"` for any S3-compatible store,
  path-style, in the given region. Requests are signed with SigV4 at the system clock, never at
  `SOURCE_DATE_EPOCH`. Redirects are not followed.
- A variable that is unset or empty is an error that names the variable and never a value, before any
  request.
- `keep` counts releases per channel by version precedence, never by text or file order. The version
  being published is never dropped, so a pre-release or hotfix older than the newest `keep` leaves one
  more listed.
- `require_targets` and `push --require-targets` combine (both must be present in the release).

### `[install.<os>]` and `pack --channel`

`[install.linux]`, `[install.windows]` and `[install.macos]` may set `entry` and `icon` only, and each
overrides the same key of `[install]` for the targets of that OS. Nothing else (a `name`, a `channel`,
a `feed`, the root, the app id) can be overridden, and an unknown OS table or key is an error. The
icon file must already be in the input tree, as for `[install] icon`. This replaces a rendered copy of
the config per OS.

```toml
[install]
entry = "bin/hello"
name = "Hello"

[install.windows]
entry = "bin/hello.exe"
icon = "assets/hello.png"
```

`pack --channel <c>` writes `c` as the channel of the update config in the packed tree instead of
`[update] channel`. It needs `[update]`, and `c` must be one of `[publish] channels`.

### `publish fetch`

Reads the public feed (`[update] feed`) over the transport a client uses and fills a new release
directory: `keys.json`, the `root-<k>.json` files after the config's root, each `[publish]` channel's
`feed-<channel>.json` that exists, and, per channel and target, the manifests and packs of the `deltas`
newest earlier releases, so that `pack` writes deltas against exactly those. It reads no credential and
prints `GET <path> <status>` for every request. `pack` and `setup` then run on that directory unchanged.

- `--release-dir` must be absent or empty; the directory is built beside its place and moved there
  when complete, so a failed fetch leaves nothing.
- `keys.json` must answer 200. A root file ends the walk on 404, 410 or 403 (M4-D10); a feed that is
  absent (404) is skipped; any other status, a TLS failure or a document that does not verify is
  exit 1. A base whose pack does not match its manifest is skipped with a line; a missing or failing
  one is exit 1.
- The documents are read with the time checks skipped, so an expired feed can still be refreshed.
- A `--version` that a feed already lists is exit 1 ("is already published"): a second `pack` of a
  published version would build different deltas.

### `publish push`

Publishes the packed release in one or more release directories (one per build job; their
`<version>/` files merge, and the same path with different bytes is exit 1).

`--sign` is required (the feeds are signed in-process with the same signers `feed add` takes).
`--dry-run` does every read and check and prints what it would upload, write and delete.
`--store-dir <dir>` uses `<dir>/public` and `<dir>/private` as the two buckets and reads no
credential; it is for tests and trials.

What it trusts and checks, before the first write:

1. It reads the state file and the pending-deletes record from the private bucket, and `keys.json`,
   the roots and each channel's feed from the public bucket through the store API with credentials
   (not through the CDN). With no state file or no `keys.json` it stops: run `publish init` first.
2. `keys.json` and every root must equal the copies `fetch` put in each release directory, and each
   feed must equal the fetched copy or already list `--version` with exactly these manifests (this
   version's own half-finished push). Anything else is exit 1: "the store changed since fetch".
3. The release must hold a manifest of `--version` for every `require_targets` target. A file under
   `<version>/` that no manifest of the release names is refused: only manifests, packs and deltas are
   published.
4. Every release a feed lists is downloaded and verified in full (manifest, pack, deltas), and so is
   the new work directory, as `verify` does. This costs about `keep` times the targets times a pack
   size of download per publish, and is deliberate: a corrupted retained pack is not left published.
5. An object that exists in the store with the same bytes is kept and reported; one with other bytes
   is exit 1, before any upload.

The version goes to `channels`, or to `prerelease_channels` when it has a pre-release part, through the
same code as `feed add`; retention drops the oldest beyond `keep` per channel through `feed refresh
--drop` with `feed_days` as the lifetime.

The commit order (every client-visible change comes after what it points to):

1. the pending-deletes record gains the version in `uploading`;
2. the new version's packs and deltas, then its manifests;
3. the record gains this run's deletes (the dropped releases' objects, taken from their verified
   manifests: no bucket listing), before any feed changes;
4. each changed feed, after re-reading it and refusing if it changed since this run read it (the race
   check);
5. the deletes: every feed is re-read first, and a pending key whose version folder any current feed
   lists is not deleted and leaves the record; a failed delete is not fatal, stays in the record and is
   printed;
6. the record as it now is, then 7. the state file, last.

`keys.json` and the roots are never written by `push` (they equal the store's). A purge key is checked
to lie under `<prefix>/` in the folder of the version it belongs to.

**Rerun and recovery.** A push that stopped part-way is completed by running `publish push` again with
the same release directories (in CI: re-run the push job; its artifacts are unchanged). Uploaded objects
are kept when byte-equal (packs are deterministic under `SOURCE_DATE_EPOCH`, so a rerun of `pack` gives
the same bytes), a feed that already lists the version is not added to again, and the rest completes.
A fresh `fetch` of a version a feed lists is refused.

### `publish refresh`

Re-signs each channel's feed with a new `seq` and expiry, the releases unchanged, then retries the
pending deletes under the same filter as `push`. With `--if-expiring-within-days N` only a feed that
expires within N days (or has expired) is re-signed; with nothing due and nothing pending it writes
nothing and exits 0. The record's deletes are retried either way, and a record key that a current feed
lists is dropped from the record undeleted. `--skip-if-unpublished` turns "no `keys.json`, no state
file or no feed in the store yet" into one `notice:` line and exit 0 (a scheduled job of an app that
has not published); without it that is exit 1. The re-signed feeds go through the same full check as
`push`, and the feed race check and the state file apply.

### `publish plan`

Read-only (it needs the store credentials). It prints each channel's feed (`seq`, expiry, releases) and,
with `--version`, what a push of it would add and drop; the pending deletes; and every version in the
record's `uploading` list that no feed lists: an abandoned push, whose folder needs a rerun of `push`
or a clean-up by hand, named with its keys from the store's manifests when they are there and verify. It
performs no put and no delete.

### `publish init`

The user's own first upload for a new app, from a release directory that `lunepack init` and
`lunepack keys set` made. It checks the directory's root walk and `keys.json` under the config's root,
takes the state file's record of this app (and no other app's), refuses when the store already holds
any document it would write (it names the first), and uploads the roots, then `keys.json`, then the
state file. An existing prefix of the same layout needs no `init`.

### `SOURCE_DATE_EPOCH` and these commands

`push`, `refresh` and `init` exit 1, naming the variable and before any network access, when
`SOURCE_DATE_EPOCH` is set: they would issue feeds at that fixed time. Set it only in the job that runs
`pack` and `setup`, to the tag commit's time. `fetch` and `plan` do not read it.

### The store layout

```
public bucket:   <prefix>/keys.json
                 <prefix>/root-<k>.json                       (after a root rotation)
                 <prefix>/feed-<channel>.json
                 <prefix>/<version>/<target>.manifest.json
                 <prefix>/<version>/<target>.pack
                 <prefix>/<version>/<target>.from-<base>.delta
private bucket:  <prefix>/lunepack-state.json                 (the publisher state file, one app's record)
                 <prefix>/lunepack-pending-deletes.json       {"format":1,"keys":[...],"uploading":[...]}
```

A command writes only keys under its `<prefix>/`; another prefix in the same buckets is never touched.
The pending-deletes record lists, sorted and without repeats, the full keys a publish dropped from every
feed and has not deleted yet, and the version folders whose objects a push began to upload before any
feed listed them.

**Limit.** Deletes come from the dropped releases' own manifests, so an object no manifest names (a file
placed by hand, the leftovers of an upload that was abandoned and never completed) is never purged
automatically. `plan` lists an abandoned push only while its version is in `uploading`; removing the
rest is the user's hand work.

### A CI job split

Generic names; the full workflow is in [`docs/PUBLISHING.md`](PUBLISHING.md).

```sh
# job "pack", one per target (the release key only; SOURCE_DATE_EPOCH from the tag commit)
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
lunepack publish fetch --release-dir release --version "$VERSION"
lunepack pack --input build --version "$VERSION" --target "$TARGET" --release-dir release \
    --sign env:EXAMPLE_RELEASE_KEY --runtime lunepack-runtime
lunepack setup release --version "$VERSION" --target "$TARGET"

# job "push", after every pack job (the release key and the store keys; no SOURCE_DATE_EPOCH)
lunepack publish push --release-dir release-linux --release-dir release-windows \
    --version "$VERSION" --sign env:EXAMPLE_RELEASE_KEY

# a scheduled job (the same secrets)
lunepack publish refresh --sign env:EXAMPLE_RELEASE_KEY --if-expiring-within-days 30 \
    --skip-if-unpublished
```

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

Upload with any tool to any static host, or with `lunepack publish` (above), which uploads in this order and
checks the store first. Order matters,
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
