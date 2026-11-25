# Getting started: a Rust app that installs and updates itself

This guide takes you from nothing to an app that is installed from a setup file and then updates
itself, with the Rust facade crate `lunepack`. An app in another language follows
[`INTEGRATION.md`](INTEGRATION.md); how to make and look after the signing keys of a real release is in
[`KEY-CEREMONY.md`](KEY-CEREMONY.md).

You work on two sides:

- **Your side (the publisher).** The `lunepack` command line packs your build output into a signed
  *release directory*: documents and packs that any static host can serve. It needs your signing keys.
- **Your user's side.** The user installs your app from a setup file. The app carries the
  *runtime* (`lunepack-runtime`, a small static program) beside it, and checks the release directory
  for new versions. The facade crate is how your Rust code talks to that machinery.

Nothing here adds a rule of its own. Where a rule matters, the guide links to the page that states it:
[`CLI.md`](CLI.md) for the packager, [`RUNTIME.md`](RUNTIME.md) for the runtime and the app's calls,
[`FORMAT.md`](FORMAT.md) for the documents.

## How the blocks below were made

Every command block was run, in a scratch directory, with keys made at that moment; the output under
it is what the command printed. The session ran on a Linux machine of the `aarch64` architecture, so
the target is `linux-aarch64` throughout: use `linux-x86_64` on an x86-64 machine. A few conventions:

- 64-character hex values (public keys, key ids) are shortened to `8 characters...4 characters`.
- The release directory is on the same machine, so the feed is a `file:///` URL. The guide's session
  lives in `/srv/demo/hello`; use your own absolute path. A real feed is an `https://` URL (step 8).
- Times, `seq` numbers and sizes are those of that session; yours differ.
- The dependency line `lunepack = "0.1"` is what an app writes. At the commit this guide was written
  against the crate is not published, so the session added a `[patch.crates-io]` entry in
  `hello/.cargo/config.toml` that points at a checkout of this repository. Nothing else in the app
  differs.
- The first block is not run: the CLI is not on crates.io at that commit.

## 1. The command line

```
cargo install lunepack-cli --locked
```

(not run: the crate is not published at this commit; the session used `cargo build --release -p
lunepack-cli` in a checkout of the repository.) It installs one program, `lunepack`.

## 2. The app

```
$ cargo new --vcs none hello
cd hello
    Creating binary (application) `hello` package
note: see more `Cargo.toml` keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html
```

`Cargo.toml`:

```toml
[package]
name = "hello"
version = "0.1.0"
edition = "2024"

[dependencies]
lunepack = "0.1"
```

`src/main.rs` is a small app with no window that does what every lunepack app does, in three steps
([`RUNTIME.md`, "The health handshake"](RUNTIME.md#the-health-handshake-d43)):

```rust
use std::io::Write as _;
use std::process::ExitCode;

use lunepack::{
    ApplyOptions, CancelToken, ConfirmOutcome, DownloadOptions, Installation, LifecycleEvent,
    StartupAction, blocking,
};

/// The app has no window, so it says what it does in a log file as well.
fn say(line: &str) {
    println!("{line}");
    let path = std::env::temp_dir().join("hello.log");
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hello: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), lunepack::Error> {
    // 1. First thing in main: learn what happened since the last start. If this version was rolled
    //    back, the previous one has been started in its place and this process must end.
    let started = lunepack::startup()?;
    let install = Installation::from_current_exe()?;
    let version = install.tree_version().to_string();
    for event in &started.events {
        match event {
            LifecycleEvent::Installed { .. } => say(&format!("{version}: installed")),
            LifecycleEvent::FirstRun { .. } => say(&format!("{version}: first run")),
            LifecycleEvent::Updated { from, .. } => say(&format!("{version}: updated from {from}")),
        }
    }
    if started.action == StartupAction::Exit {
        say(&format!("{version}: rolled back, ending"));
        return Ok(());
    }
    say(&format!("{version}: hello"));

    // 2. Once the app works, confirm it. Without this, every update is rolled back.
    if lunepack::confirm_healthy()? == ConfirmOutcome::Confirmed {
        say(&format!("{version}: confirmed"));
    }

    // 3. On request, look for an update and, when there is one, hand over to the runtime.
    if std::env::args().any(|a| a == "--update") {
        let updater = blocking::Updater::from(install.updater_builder()?.build()?);
        let cancel = CancelToken::new();
        let Some(info) = updater.check(&cancel)? else {
            say(&format!("{version}: no update"));
            return Ok(());
        };
        say(&format!("{version}: update {} found", info.version()));
        let downloaded = updater.download(&info, DownloadOptions::default(), &cancel)?;
        let staged = updater.stage(downloaded, &cancel)?;
        say(&format!("{version}: staged {}", staged.version()));
        lunepack::apply_and_restart(ApplyOptions {
            expect_version: Some(staged.version().clone()),
            ..ApplyOptions::default()
        })?;
        // The runtime applies the update once this process has ended, and starts the new version.
        say(&format!("{version}: restarting"));
    }
    Ok(())
}
```

What each call does, and what the app has to do (all of it is in [`RUNTIME.md`](RUNTIME.md)):

- `startup()` runs at every start, first. It delivers the events queued for this version (`installed`,
  `first_run`, `updated`, each once) and says whether to go on. When the action is `Exit`, this version
  was rolled back and the previous one has already been started: the app ends at once.
- `confirm_healthy()` says "this version works". A new version is started with a health token in its
  environment and is rolled back unless it confirms. An app that never confirms has every update
  rolled back ([`RUNTIME.md`, "The health handshake"](RUNTIME.md#the-health-handshake-d43)). With nothing pending it
  succeeds and does nothing, so the app may call it on every start.
- `Installation::from_current_exe()` finds the app's own install from its executable's path, and
  `updater_builder()` builds an updater from that install's update configuration: the app id, the
  trusted root, the feed and the channel. The app never works out the install root itself
  ([`RUNTIME.md`, "Locating the runtime"](RUNTIME.md#locating-the-runtime)).
- `check`, `download` and `stage` fetch and verify the update and prepare its tree. They are plain
  blocking calls here; the same futures run on any async executor (the crate's documentation shows
  tokio, smol and none).
- `apply_and_restart()` hands over to the runtime and the app then ends; the runtime waits for this
  process to exit, switches to the new version and starts it with the health token
  ([`RUNTIME.md`, "Apply and restart"](RUNTIME.md#apply-and-restart)).

```
$ cargo build --release
...
    Finished `release` profile [optimized] target(s) in 23.44s
```

## 3. The keys

Two kinds of key sign a release. The **root** keys sign the list of release keys and any change of
root; they stay offline. The **release** keys sign the feed and the manifests; your build machine
uses them. Clients hold only the public root keys (they are in the app's update configuration). This
walk-through makes one of each; [`KEY-CEREMONY.md`](KEY-CEREMONY.md) says how to do it for a real app.

```
$ mkdir keys
ROOT=$(lunepack keys gen keys/root | sed -n 's/^public: //p')
RELEASE=$(lunepack keys gen keys/release | sed -n 's/^public: //p')
wrote the private key to keys/root.key
wrote the private key to keys/release.key
```

`keys gen` writes a private key file (mode 0600, never over an existing file; the directory must exist),
prints `public:` and `id:` on stdout and its own message on stderr. The two commands above keep the
public keys in shell variables for the next steps. To see them again:

```
$ lunepack keys show --sign file:keys/root.key
public: 3f5ef13d...56bd
id: 9100a21b...70fb
```

## 4. The configuration

```
$ lunepack init --app-id org.example.hello --root-key "$ROOT"
wrote lunepack.toml
wrote lunepack-state.json
```

`init` writes `lunepack.toml`, which holds public keys and the places to find signers and never a key,
and `lunepack-state.json`, the publisher's memory of what it last signed (below). Add the signers
(where the private keys are), `[update]` (where clients look) and `[install]` (what to install):

```toml
[signers.root]
file = "keys/root.key"

[signers.release]
file = "keys/release.key"

[update]
feed = "file:///srv/demo/hello/release/"

[install]
entry = "hello"
name = "Hello"
bin = "hello"
```

- `[update] feed` is the URL of the release directory as a client reaches it. It is written into
  every pack, so set the real one before you pack a release users will install. It must pass the feed
  rule of [`FORMAT.md` section 13.3](FORMAT.md): `https://` with a DNS name, `file:///`, or `http://` to a
  loopback address.
- `[install] entry` is the app's executable inside the tree you pack; `name` is the display name;
  `bin` names a command-line link. All the fields are in [`CLI.md`](CLI.md), "Configuration".

Then sign the list of release keys, once:

```
$ mkdir release
lunepack keys set --release-dir release --release-key "$RELEASE" --sign root
change: a first key set: 1 key(s), threshold 1
keys.json: version 1, root 1, 1 key(s), threshold 1
```

`keys.json` is signed by the root key and lists the release key. A leaked release key is revoked by
signing a new `keys.json` without it ([`CLI.md`, "Revoking a release key"](CLI.md#revoking-a-release-key)).

## 5. The runtime

`lunepack pack --runtime` takes the runtime as a file and places it beside your app's entry; the pack's
signed manifest then covers it. There are two ways to get one.

The runtime, the window program (`lunepack-ui`), the Windows stubs and the update service of a lunepack
release are downloaded by `lunepack prebuilt fetch`, which checks every file against the hashes pinned
inside the CLI ([`CLI.md`](CLI.md), "`lunepack prebuilt fetch`"). A CLI built from this repository has no
project key built in, so nothing is pinned and the command refuses:

```
$ lunepack prebuilt fetch --target linux-aarch64 --out runtime
error: prebuilt fetch needs this CLI in the state pinned, it is in the state no-key: no project key is built in, so nothing is pinned
```

The other way is to build the runtime from a checkout of the repository. For Linux that is a static musl
build; the target must be installed with `rustup target add`
([`CLI.md`](CLI.md), "Building the runtime"):

```
$ HERE=$PWD
cd ~/lunepack
./scripts/build-runtime.sh linux-aarch64 --out "$HERE/lunepack-runtime"
cd "$HERE"
...
copied to: /srv/demo/hello/lunepack-runtime
...
static: yes (aarch64-unknown-linux-musl, no PT_INTERP, no NEEDED)
size: 6296224 bytes
```

(The `...` lines stand for the build's own progress and for the path of its build directory; `~/lunepack`
is the checkout.)
`pack` never builds anything and never uses the network.

## 6. Pack and publish version 1.0.0

`pack` takes the folder that holds the app as it is to be installed:

```
$ mkdir input
cp target/release/hello input/hello
```

```
$ lunepack pack --input input --version 1.0.0 --target linux-aarch64 \
    --release-dir release --sign release --runtime lunepack-runtime
binary: --runtime is a local build
delta: base(s) none
assemble: copied input
update: placed the runtime and the update config
code-sign: 0 item(s)
hash: 4 file(s), 0 dir(s), 0 symlink(s), 14116580 bytes
pack: 4 distinct file(s) encoded on 4 worker(s)
sign: manifest signed by 1 key(s)
verify: manifest, pack and 4 frame(s) ok
placed: release/1.0.0/linux-aarch64.pack
placed: release/1.0.0/linux-aarch64.manifest.json
totals: 4 file(s), 14116580 input bytes, 3675598 pack bytes
codec bcj-arm64+lzma2: 2
codec lzma2: 2
```

Four files are packed: your app, the runtime, the update configuration `pack` wrote
(`lunepack-update.json`) and the third-party notices file. The `binary:` line says whether the runtime is
one of lunepack's pinned release binaries; `--require-pinned` makes a local build an error
([`CLI.md`](CLI.md), `pack`). `pack` verifies its own output the way a client does before it writes it.
Nothing in a release directory is overwritten: a second `pack` of the same version is refused.

A pack is not visible to clients until a feed lists it:

```
$ lunepack feed add --release-dir release --channel stable --version 1.0.0 --sign release
verify: 1.0.0/linux-aarch64.manifest.json and its pack ok (4 frame(s))
placed: feed-stable.json (seq 1795581383000, 1 release(s), 1 manifest(s) verified)
```

`feed add` can also set a rollout (a share of installs) and an expiry (default 90 days; `feed refresh`
signs a new one). Now check the directory the way a client does, and look inside:

```
$ lunepack verify release
root: version 1 ok
keys.json: version 1, 1 key(s), threshold 1 ok
feed-stable.json: seq 1795581383000, 1 release(s) ok
1.0.0/linux-aarch64.manifest.json: manifest and pack ok (4 frame(s) decoded)
verified: 1 feed(s), 1 manifest(s), 0 unreferenced
```

```
$ lunepack inspect release
keys: version 1, root 1, threshold 1, no expiry
  key b8d5e025...9baf: valid 1795581377..1858653377
feed stable (feed-stable.json): seq 1795581383000, issued 1795581383, expires 1803357383, 1 release(s)
  release 1.0.0: rollout everyone, 1 target(s)
    linux-aarch64: issued 1795581380, 4 file(s), 0 dir(s), 0 symlink(s)
      input 14116580 bytes, pack 3675598 bytes (26.0% of input), 0 empty file(s)
      codecs: bcj-arm64+lzma2=2 lzma2=2
```

## 7. The publisher state file

`lunepack-state.json` is next to `lunepack.toml`. It records, per app, the root version, the key-set
version and each channel's `seq` that you last signed, so a writer refuses to build on an older
document that someone put back in the release directory. Keep it with the config, in your own storage;
in CI, commit it or save it around the job, and never fetch the release directory from the public
host as the base for writing ([`CLI.md`, "The publisher state file"](CLI.md#the-publisher-state-file-m3-r2-d1)).
One state file records one release directory per app, so a second release directory of the same app
(staging and production, say) needs its own config directory or its own `state` path, or its writers are
refused for the documents the other directory recorded.

## 8. Host the release directory

Upload the directory to any static host: an object-store bucket behind a CDN, or a plain web server.
There is no server software of lunepack's to run. Upload in this order, so that a client never sees a
document whose files are missing: the packs and delta files, the manifests, `root-<k>.json` and
`keys.json`, and the feeds last ([`CLI.md`, "The release directory"](CLI.md#the-release-directory)). The
URL is the `[update] feed` of the config, for example `https://updates.example.org/hello/`.

```
https://updates.example.org/hello/keys.json
https://updates.example.org/hello/feed-stable.json
https://updates.example.org/hello/1.0.0/linux-aarch64.manifest.json
https://updates.example.org/hello/1.0.0/linux-aarch64.pack
```

(not run: a host is yours to choose; the rest of this guide serves the same files from the local
directory through the `file:///` feed.)

## 9. The first install

`lunepack setup` builds a file that installs exactly one version with no network:

```
$ lunepack setup release --version 1.0.0 --target linux-aarch64
setup: org.example.hello-1.0.0-linux-aarch64-setup (9978960 bytes)
```

Give that file to a user. Run with `--silent` it installs without a window and prints one result line
on stdout (its progress goes to stderr, hidden here):

```
$ ./org.example.hello-1.0.0-linux-aarch64-setup --silent 2>/dev/null
{"schema":1,"type":"result","command":"setup","tree_version":"1.0.0","outcome":"installed","version":"1.0.0"}
```

On Linux the per-user install is in `~/.local/share/org.example.hello`, with the version trees in
`versions/` ([`RUNTIME.md`, "Locating the runtime"](RUNTIME.md#locating-the-runtime)), and `bin = "hello"`
made the link `~/.local/bin/hello`. Start the app through it:

```
$ ~/.local/bin/hello
1.0.0: installed
1.0.0: first run
1.0.0: hello
```

The first start delivered the events `installed` and `first_run`. `confirm_healthy()` said nothing:
this version was not started by an update, so nothing was waiting for a confirmation.

A setup file built with `--ui` (the window program) shows a window, and one built with `--service` can
install for all users ([`RUNTIME.md`, "Setup files"](RUNTIME.md#setup-files) and "Per-machine installs").

## 10. The first update

Build your next version, pack it and add it to the feed. Here the app did not change, which is a valid
release; a real one has new files:

```
$ lunepack pack --input input --version 1.1.0 --target linux-aarch64 \
    --release-dir release --sign release --runtime lunepack-runtime
binary: --runtime is a local build
delta: base(s) 1.0.0
assemble: copied input
update: placed the runtime and the update config
code-sign: 0 item(s)
hash: 4 file(s), 0 dir(s), 0 symlink(s), 14116580 bytes
pack: 4 distinct file(s) encoded on 4 worker(s)
delta: 1 base(s), 1 delta file(s)
sign: manifest signed by 1 key(s)
verify: manifest, pack and 4 frame(s) ok
verify: 1 delta file(s) and 1 patch(es) ok
placed: release/1.1.0/linux-aarch64.pack
placed: release/1.1.0/linux-aarch64.from-1.0.0.delta
placed: release/1.1.0/linux-aarch64.manifest.json
totals: 4 file(s), 14116580 input bytes, 3675598 pack bytes
codec bcj-arm64+lzma2: 2
codec lzma2: 2
delta: from 1.0.0: 1 patch(es), 20 bytes for 350 bytes of frames
```

```
$ lunepack feed add --release-dir release --channel stable --version 1.1.0 --sign release
verify: 1.0.0/linux-aarch64.manifest.json and its pack ok (4 frame(s))
verify: 1.1.0/linux-aarch64.manifest.json and its pack ok (4 frame(s))
placed: feed-stable.json (seq 1795581387000, 2 release(s), 2 manifest(s) verified)
```

`pack` also wrote a delta file against 1.0.0 ([`CLI.md`, "Deltas"](CLI.md#deltas-m12-formatmd-93)): an
installed 1.0.0 downloads a patch of 20 bytes for the one file that changed, not the files again. Now ask
the installed app to update:

```
$ ~/.local/bin/hello --update
1.0.0: hello
1.0.0: update 1.1.0 found
1.0.0: staged 1.1.0
1.0.0: restarting
```

The app exits after `restarting`. The runtime waits for it, switches to 1.1.0 and starts it; the new
version's output goes nowhere, which is why the app also writes its log file:

```
$ cat /tmp/hello.log
1.0.0: hello
1.0.0: update 1.1.0 found
1.0.0: staged 1.1.0
1.0.0: restarting
1.1.0: updated from 1.0.0
1.1.0: first run
1.1.0: hello
1.1.0: confirmed
```

The last four lines are the new version: `startup()` delivered `updated` and `first_run`, and
`confirm_healthy()` returned `Confirmed`, which is what keeps the update. The next start finds 1.1.0
current:

```
$ ~/.local/bin/hello
1.1.0: hello
```

If 1.1.0 had crashed, or had not confirmed within the health timeout (`[update] health_timeout_secs`,
default 60 seconds), the runtime would have started 1.0.0 again and marked 1.1.0 as bad on this install,
so it is never offered again. [`INTEGRATION.md`](INTEGRATION.md) shows that with a real run.

## 11. Windows and macOS

The steps are the same; what differs is the shape of the input and the files `pack` needs.

- **Windows.** Add `--stub <lunepack-stub.exe>` to `pack` (the console stub when `install.terminal` is
  set) and use `windows-x86_64` as the target; the runtime and the stub are Windows executables that
  `prebuilt fetch --target windows-x86_64` downloads. `setup` writes a `-setup.exe` file. Sign the files
  your own way; `[codesign.windows]` runs your signing tool
  ([`CLI.md`, "Windows targets"](CLI.md#windows-targets-m7) and "Code signing").
- **macOS.** The input is a ready `.app` bundle, `install.entry` is `Contents/MacOS/<file>`, and
  `setup` writes an installer `.dmg` or a `.zip`. Mind the rule about files in `Contents/MacOS`
  ([`INTEGRATION.md`](INTEGRATION.md#macos-the-bundle-layout) and [`CLI.md`, "macOS targets"](CLI.md#macos-targets-m8)).
- (not run: this guide's session was a Linux machine.)

## Where to go next

- [`INTEGRATION.md`](INTEGRATION.md): the same cycle for an app in any language, driven only by the
  runtime's command line, with a .NET example.
- [`KEY-CEREMONY.md`](KEY-CEREMONY.md): making and keeping the offline root, thresholds, rotating and
  revoking keys, and what a leak costs.
- [`CLI.md`](CLI.md) and [`RUNTIME.md`](RUNTIME.md): every option, output and exit code.
- [`FORMAT.md`](FORMAT.md): the documents and the order in which a client checks them.
