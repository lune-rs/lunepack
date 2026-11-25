# Architecture

How the workspace is split and how the split is enforced. Crate roles and the boundary rules
are the current design; the traits below are defined. The wire
format is `docs/FORMAT.md` and its threat model `docs/THREAT-MODEL.md`. Decisions behind this are in
the project's internal decision log, which is not part of this repository (D1, D6, D14, D17, D23, D26, D28, D30, D31, D33, D35 to D41, M2-D1 to M2-D9,
M3-D1 to M3-D13, M4-D1 to M4-D23, M5-D2 to M5-D20, M6-D1 to M6-D15, M7-D1 to M7-D22, M8-D1 to M8-D20, M10-D1 to M10-D20, M11-D1 to M11-D16).

## Crates

| Crate | Role | May depend on |
|---|---|---|
| `lunepack-core` | Types, rules, verification policy, planning, state machine, apply engine; owns every trait and the error enum. No I/O, clock, randomness or network of its own. Today: strict JSON, DSSE envelopes, root rotation, key sets, feeds, manifests, frame descriptors, the path, version and target rules, update policy, and the hidden `fuzz` harness module. Since M4 also the sans-IO client logic: the transport traits and the pure HTTP response rules (`Content-Range`, validators, encoding, fetch planning), the `Fs` trait, the install-state store (records, commit and load, scopes, transitions; FORMAT.md 12), the stage engine (scan for unchanged files, bounded parallel decode within a memory budget, resume, `NeedFetch`), the `CancelToken` and the progress event types. Since M6 also the UI port (`ui`: the messages between the engine and the UI process, the capped and fail-closed frame codec, the build id and the flow reducers; below), the setup file's trailer (`setup`: FORMAT.md 14) and the offline payload verification (`verify_payload_manifest`, `read_entry`; M6-D4). The one use of threads in the core is `std::thread::scope` (and `std::thread::panicking`) in the stage engine, because the worker count comes from the caller, so the output never depends on the machine; it uses no clock, environment, filesystem or network, the purity test allows exactly those two paths in `stage.rs`, and any other thread use in the core stays forbidden (M4-D12, user decision Q30, 2026-11-14). Since M10: the privileged **engine** (`engine.rs`: first install, stage, apply, attempt, confirm, rollback, service switch, garbage collection, repair, uninstall, one `serve` loop over a protocol connection; it is the only writer of a per-machine install and trusts only the machine record and the admin-only tree), the **service protocol** codec with its client and server sessions (`service.rs`, FORMAT.md 19), the shared chain walk (`chain.rs`) the library and the engine both verify with, the machine state store and lifecycle transitions (`state.rs`, `lifecycle.rs`), the machine layout (`MachineLayout`, FORMAT.md 18) and the setup anchor (`setup.rs`, FORMAT.md 14.5). Since M11 also the machine schemes (`MachineScheme`: one set of directory names on every OS and three projections, none on Windows, `R/current` on Linux, the bundle swap on macOS, run by the engine after every commit; FORMAT.md 20), the endpoint names of the unix services (`endpoint.rs`) and the unix protection rule as a pure function over the facts an adapter reads (`unix_protect.rs`, M11-D7). | nothing external beyond an explicit allowlist: `serde`, `serde_json`, `base64`, `semver`, `unicode-normalization`, `thiserror` (M2-D1) |
| `lunepack-testkit` | In-memory fakes and the contract suites. Today: a fake clock, hasher, signature scheme and codec (with fault knobs), the contract suites for the traits below, document builders over the core's real writer, and the fuzz seed writer; `MemFs`, an in-memory `Fs` that injects a crash at any operation and recovers under a chosen durability mode; `FakeTransport` and `FakeBlockingTransport` over a `FakeOrigin` (Range, `If-Range`, validators, redirects, a request log and fault knobs such as an ignored Range, a wrong `Content-Range`, a truncated, endless or one-byte-chunk body); and `LoopbackServer`, the same origin over a real `127.0.0.1` socket; and, since M5 step 3, `FakeRng`, `FakeProcess` and `FakeIntegration` with their suites. `publish = false`. Since M10: fakes and contract suites for the machine-install ports (below) and the in-memory machine tree the engine's end-to-end tests run over (`machine.rs`), and the service protocol's fuzz seeds. | core |
| `lunepack-crypto` | Hashing and signature verification adapters: SHA-256 and Ed25519 with strict verification; and the signers (M3): `Ed25519Signer` over PKCS#8 PEM from a file or an environment variable, `generate_key_file`, and `CommandSigner` (an external command whose signature is verified before use). Nothing it prints or returns in an error holds key material. | core |
| `lunepack-codec-lzma` | Compression adapter over `lzma-rust2` (confined to this crate, M3-D11): the `Codec` decoder with limits from the signed descriptor, and the `Encoder` at the 9e settings for all five codec ids (stored, LZMA2, BCJ x86 and ARM64 + LZMA2, BCJ2). Since M12 it also decodes and encodes delta patches (`Codec::decode_patch`, `Encoder::encode_patch` for `lzma2`, `bcj-x86+lzma2` and `bcj-arm64+lzma2`, the base as the preset dictionary, `docs/FORMAT.md` 9.3). | core |
| `lunepack-fs` | Filesystem adapter: `StdFs`, the `Fs` implementation over `std::fs` (it refuses symlink components when it creates directories, and syncs files and directories), and the OS lock behind `Fs::try_lock` through `fs4` (released by the OS when its holder dies). May lift `unsafe_code`; documents that Windows directory durability is an unverified assumption. Since M8 on unix it implements `place` and `create_dir_private` (`statfs`, `faccessat`), and on macOS `exchange` through `renamex_np(RENAME_SWAP)` (`ENOTSUP` is `Unsupported`; there is no fallback in the adapter) and a `copy_file` that copies data and mode only, because std's copy carries `com.apple.quarantine` (M8-D10). | core |
| `lunepack-http` | Release source and network adapter: `UreqTransport`, the default `BlockingTransport` (ureq 3.5 with the OS platform verifier for TLS and the system proxy: environment first, then WinINET on Windows and the system proxy through hyper-util on macOS; no content decoding, `User-Agent: lunepack` only) and `DirSource`, which serves `file:` URLs under one root with Range support. The only crate that reaches `ring` (below). It also holds an `os_trust` example that CI runs through the real adapter. | core |
| `lunepack-os-windows` | The Windows adapters (M7), through `windows-sys` and, for the Start-menu shortcut's COM interfaces, the `windows` crate (M7-D4; reachable only through this crate and the UI adapter). `WindowsProcess` implements `Process` over the Win32 process APIs (spawn without a shell, detach, wait by pid and start time, terminate only its own child, the in-use scan of a tree). `WindowsIntegration` implements `OsIntegration`: the launcher stub at the install root (replaced in one rename, or the running copy renamed aside; `remove_stub_leftovers` for the collection), the hidden `.lunepack` directory, the `HKCU` uninstall entry, the Start-menu shortcut with the app's app user model id, and the file types, URL schemes and autostart value the app declares; each entry carries a marker and anything without it is a conflict, never overwritten. Safe helpers that build on every OS (no-ops or `Unsupported` off Windows): the DLL search hardening every shipped Windows binary calls first in `main` (`harden_dll_search`), known folders, a native message box, the process's app user model id, the foreground right, and the launcher's raw command line and console-interrupt helpers, plus the reduce-motion reader of M6-D8. One of the crates that may lift `unsafe_code`, each block with a `// SAFETY:` comment. Since M9 also `WinPublisherCheck`, the `PublisherCheck` of the Windows platform over `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, no user interface, no revocation lookup, cache-only URL retrieval: never the network): the leaf signers' subject names (`CERT_INFO.Subject`, compared as DER) of the installed and the candidate entry executables, and every other PE of the candidate trusted under any publisher (M9-D8); every status outside its allowlist is `os` (M9-R1-D2). Its `unsafe` module is the only new FFI. Since M10 (all new `unsafe` of the per-machine install lives here): protected directories with explicit security descriptors and the descriptor check (`WindowsProtect`), the named-pipe server and client with real read deadlines and the owner check (`PipeServer`, `PipeClient`), the Service Control Manager registrar, connector and dispatcher (`WindowsRegistrar`, `WindowsConnector`, `run_service`), the machine integration scope (HKLM, the all-users Start menu), the policy source (`RegistryPolicy`), the elevation hand-off through `ShellExecuteExW` (`WindowsElevation`), token queries, the `RT_RCDATA` resource reader and `Process::tree_in_use_strict` with its file-system probe. | core |
| `lunepack-os-macos` | The macOS adapters (M8), through `libc` and libproc. `MacProcess` implements `Process`: spawn without a shell (`std::process`; a detached start leads a new session), identity by pid and start time in microseconds so a reused pid is never mistaken for the original, a wait for a process that is not our child by kqueue with a periodic look (it never signals or reaps it), termination of only its own child, and the in-use scan over libproc (executable, working directory and open files of every process of the user, compared with the tree as the kernel names it, so a swap that moved a running app's tree is seen; the two exceptions and the gaps are in `docs/THREAT-MODEL.md`). `spawn_app_background` starts an app through `/usr/bin/open -g -n -W` run as our child with the token in `open`'s environment only, and identifies the app as exactly one new process with the entry's path, our uid and a later start time; an unidentified app is never signalled (M8-D13). `MacIntegration` implements `OsIntegration` (the LaunchAgent, M8-D12); `notice` shows a native alert through `osascript` with a fixed script and the text as arguments (M8-D11); the reduce-motion reader of M6-D8 (`defaults`). One of the crates that may lift `unsafe_code`, each block with a `// SAFETY:` comment. Since M9 also `MacPublisherCheck` over Security.framework (`security-framework` as a direct dependency, plus two own `extern "C"` declarations and one `unsafe` module with `// SAFETY:` comments, M9-D10): the candidate bundle must pass a strict, nested, all-architecture static validation without network access and satisfy the installed bundle's designated requirement; an ad-hoc signature counts as unsigned (M9-D7). Since M11 (the new `unsafe` of the macOS per-machine install lives here, each block with a `// SAFETY:` comment): protected directories with the unix rule and the extended-ACL read (`MacProtect`), the launchd registrar for the system-domain LaunchDaemon and the stable service link (`LaunchdRegistrar`), the listener from `launch_activate_socket` and the connector that checks the socket's folder, its owner and the peer's uid through `getpeereid` (`ActivatedListener`, `UnixConnector`), the policy file, the machine autostart LaunchAgent (`MacMachineIntegration`), the elevation's standing (no prompt of our own, D38 (a)) and `Process::tree_in_use_strict` over every process of every user. | core |
| `lunepack-stub` | Binaries `lunepack-stub` (Windows subsystem) and `lunepack-stub-console` (console subsystem; M7-D7): the launcher the packager stamps and places beside a Windows app's entry, and that the runtime copies to the install root. It implements the launch contract of `docs/FORMAT.md` 15 over the core's read path (`launch_target`) and starts the app. It links the core, the filesystem adapter, the Windows helpers and `lunepack-crypto` only for SHA-256 of the install record's checksum (M7-D20), and nothing else: no facade, no network, no codec, no UI; the boundary check holds the list (`DEPENDS_ONLY_ON`). Off Windows both binaries print one line and exit 2, so the workspace builds everywhere. | core, adapters |
| `lunepack-service` | Binary `lunepack-service.exe` on Windows (M10-D7) and `lunepack-service` on Linux and macOS (M11): the update service of a per-machine install, the **third composition root**. The Windows service control manager starts it as LocalSystem, demand start, one per app; on Linux systemd (a socket unit with `Accept=no`) and on macOS launchd (a LaunchDaemon with a socket) start it as root on demand and hand it the listening socket (M11-D3). It opens the privileged engine of the install its own image path names and serves it over one named pipe or unix socket, one connection at a time with deadlines on every read, and exits after 60 s with no connection and no lease. It reads no environment variable and no working directory, never impersonates, logs fixed lines to a capped file, and updates its own binary through a `--self-test` switch. The boundary check limits it to the core, `lunepack-fs`, `lunepack-crypto`, `lunepack-codec-lzma` and the three OS adapters (`lunepack-os-windows`, `lunepack-os-linux`, `lunepack-os-macos`): no HTTP stack, no UI. | core, fs, crypto, codec-lzma, os-windows, os-linux, os-macos |
| `lunepack-os-linux` | The Linux adapters (M5): `LinuxProcess` implements `Process` over `/proc` and `libc` (spawn without a shell, detach, wait by pid and start time so a reused pid is not mistaken for the original, terminate only its own child, the in-use scan of a tree), and `XdgIntegration` implements `OsIntegration` (the desktop entry `<data home>/applications/<app id>.desktop` built fail-closed from the update configuration, the command link in `~/.local/bin`, removal checked by a marker). `LinuxProcess` also starts a child with piped standard input and output for the UI channel (`ChildStdio::Piped`; the parent's ends are close-on-exec, M6-D1), and `prefers_reduced_motion` reads `gsettings` (M6-D8). One of the crates that may lift `unsafe_code`, each block with a `// SAFETY:` comment. Since M9 also `NoPublisherCheck`, whose answer is always "not applicable" (Linux has no OS code-signing identity to compare). Since M11 (the new `unsafe` of the Linux per-machine install lives here, each block with a `// SAFETY:` comment): protected directories with the unix rule and the ACL read (`LinuxProtect`), the systemd registrar for the socket and service units and the stable service link (`SystemdRegistrar`), the activated listener over descriptor 3 and the connector that checks the socket's folder, its owner and the peer's uid through `SO_PEERCRED` (`ActivatedListener`, `UnixConnector`), the policy file (`FilePolicy`), the `pkexec` hand-off (`PkexecElevation`), the system-wide integration under `/usr/local` and `/etc/xdg` (`MachineIntegration`) and `Process::tree_in_use_strict` over every process of every user. | core |
| `lunepack` | The app-facing facade and the composition root for apps that embed lunepack: `UpdaterBuilder` wires the default adapters (`WorkerTransport` over `UreqTransport` for `http(s)`, `DirSource` for `file:`, `StdFs`, the LZMA codec, SHA-256 and Ed25519 from `lunepack-crypto`, `SystemClock`), each swappable. `Updater` offers `check`, `download`, `stage` as `Send + 'static` futures that need no particular executor, the synchronous `installed` and `staged`, and `lunepack::blocking` for apps without a runtime. Under it, std-only task plumbing (worker jobs, bounded pipes, a built-in `block_on`, `WorkerTransport` that runs any `BlockingTransport` on worker threads, progress coalescing) and the fetch engine (documents, feed URLs, the cache, Range runs, pack resume, the full-pack fallback) (M4-D1 to M4-D3). Also `SystemClock` (M3-D5), the only wall-clock `Clock`. Since M5 it also finds an installed app from its own executable (`Installation`, which reads the update configuration of the tree and derives the install root `R`) and offers the lifecycle calls over the core's transitions: `startup`, `confirm_healthy`, `apply_and_restart` and `Updater::install` (M5-D2 to M5-D8), and since M6 `Updater::install_from_payload`, the first install from a setup file's own frames with no feed and no network (M6-D4), and the `UiChoice` of `apply_and_restart` (D41); it wires the Linux process and integration adapters, and on Windows (M7) `WindowsProcess`, `WindowsIntegration`, the programs folder and the Windows layout scheme, in `Platform::native`, and sets the process's app user model id in `startup`, and on macOS (M8) `MacProcess`, `MacIntegration`, the canonical data home and the bundle layout scheme, finding the install from the running bundle's path (`Installation`: location first, then the install, a moved bundle, or an adoptable one) and offering `Updater::check_with` (which adopts a dragged bundle after proving it equal to its release), `ApplyOptions::background` and the bundle forms of `install` and `install_from_payload`. Since M10 it also finds a per-machine install by the running tree's location, reads the machine record, and sends every change to the install's update service through the core's protocol client (`stage`, `attempt`, `confirm`); it writes only the user's own home (`machine.rs`). | core, adapters |
| `lunepack-runtime` | Binary, static musl on Linux and a Windows-subsystem binary with a static C runtime on Windows (M7-D6, M7-D10), one per version tree and placed beside the app's entry by the packager (D28, M5-D7). Its composition root (`main.rs`) wires the Linux adapters and runs a mode named on its command line: `apply` (started detached by `apply_and_restart`: wait for the app to exit, commit the staged version, flip `current`, start it with a health token, supervise it, roll it back if it fails or does not confirm in time, then collect old trees), `install` (the first install from a bootstrap tree) and `uninstall`. Progress and results are schema-1 JSON events on its log (`R/logs/runtime.log`) or stderr; every outcome has a stable exit code. It does its work through the facade, and the same calls back the app-facing command line of D42 (`check`, `download`, `startup`, `confirm`: JSON Lines schema 1 and stable exit codes, `docs/RUNTIME.md`). Since M6 it also owns the engine's side of the UI channel (`UiHost`, below) and the setup mode (a runtime that carries a setup trailer installs its own payload, `docs/RUNTIME.md`). On macOS (M8) it also wires `MacProcess` and `MacIntegration`, starts the update window from the helper app, runs the installer app's setup mode (`--ui-stdio`, where the UI is its parent), uninstalls the bundle and its root, and refuses a place it cannot update with exit 28. The service is a later milestone. Since M10 it also hosts the engine in three elevated modes that run once (`machine-install` inside `Setup.exe`, `machine-repair`, `machine-uninstall`), is the service's client when it applies an update, and chooses between a per-user and an all-users install (`machine.rs`, `relay.rs`). Since M11 the same on Linux (the all-users install by `pkexec` of the setup file, `machine-install --events stdout`, events relayed from the child's standard output; the root `--all-users` run; the `sudo` command screen) and macOS (`machine-install --pkg`, the `postinstall` of the installer package, and the window's hand-off to Installer), with `repair` and `uninstall` on both (the unelevated Linux uninstall's own copy, the root uninstall in two phases through `exec`). | core, adapters, facade |
| `lunepack-cli` | Binary `lunepack` and the packager's composition root: `init`, `keys`, `pack`, `feed add` and `refresh`, `verify` and `inspect` (`docs/CLI.md`). It holds the I/O the core must not have: `lunepack.toml`, signer specs, the release-directory walk, the pack pipeline (assemble a temporary copy, code-sign, hash, pack on a worker pool within a memory budget, sign), self-verification of every output with the core verifiers, and placement by temp file and rename; since M6 also `pack --ui` and `setup`, which builds a Linux setup file, and since M7 `pack --stub` and the Windows setup file: it stamps the stub's and the setup runtime's icon and version information with `editpe` (confined to this crate, M7-D22) and checks that the stamp kept the hardening; since M8 `pack` for `macos-*` targets (bundle rules, the helper app, the signed-bundle rule and `--assemble`, generated `Info.plist` files) and `setup` for them: the installer `.dmg` through the system's `hdiutil`, and a `.zip` through its own writer over `flate2` (M8-D9, a direct dependency of this crate only). Pure rules (codec choice, layout, manifest, signing, document writers) stay in the core (M3-D1). Since M9 it also runs the OS sign stage (`codesign.rs`): `OsCodeSign` signs the items of the core's sign plan, inner to outer, through the developer's argv templates (`[codesign.<os>]`) over one bounded process runner (`tool.rs`: no shell, capped and redacted output, timeouts), checks after every call that the item really is in a signed form, and for a `macos-*` bundle verifies, notarizes, staples and checks the ticket before hashing; `lunepack setup` signs the setup file and the installer app and image the same way (CLI.md, "Code signing"). Since M10 `pack --service` places the update service beside the entry, and `setup` stamps and patches the setup anchor. Since M13 it also carries the project's key sets and the pin list of its own version (`prebuilt list`, `check`, `sign`, `verify` and `fetch`; `pack` classifies the binaries it is given as pinned or local), and it reads the trust chain through the core's root walk, as a client does. | core, adapters, facade |
| `lunepack-ui-luneui` | The UI adapter (M6): the screens of the install, update and uninstall flows, drawn with LuneUI (the "B revised" look with its motion, keyboard and accessibility tree, in opaque material on Linux). It holds a pure model over the core's reducers (`UiModel`; a frame is a pure function of the model and the time, so every screen and every animation step renders headless at a fixed time), the screens, the icon decoder (PNG only, capped, M6-D11), the bundled RznSans fonts, the headless renderer the golden tests use, and the demo example. It decides nothing, reads no file and starts no process; the engine does every one of those. The only crate that may depend on `lune-ui`, the one dependency from a git source (D39 (b)); the GPU and window stack under it (`wgpu`, `winit`, AccessKit) is reachable only through it (below). `publish = false`. | core |
| `lunepack-ui` | Binary `lunepack-ui` (M6): the separate process the runtime spawns to show those screens (`--engine`; and since M8, with no argument, as the main executable of a macOS installer app, where it starts the runtime beside it with `--ui-stdio` and is that runtime's parent, M8-D7). It owns the winit event loop, the window and the GPU surface, the AccessKit bridge, and the two channel threads: a reader that decodes the frames on standard input and posts them to the loop, and a writer that sends the answers on standard output and writes nothing else. It reads the OS's reduce-motion setting (M6-D8) and ends with a typed exit code (below). The only crate that depends on `lunepack-ui-luneui`, and no crate depends on it. `publish = false`. | core, adapters |
| `xtask` | Repository tooling: the boundary check (which also holds the publish set), the key-container file check, the optional denylist scan and the generated third-party notices (`notices`). | nothing in the workspace |

A language binding (a C ABI crate, later others) is one more adapter crate over the core and adds no logic.
Ten crates are published to crates.io, all at one version and depending on each other with `=` requirements, because they are released together and their internals are not a stable interface: the facade `lunepack`, the packager `lunepack-cli` (it installs the `lunepack` command), and the eight crates they need (`lunepack-core`, `lunepack-crypto`, `lunepack-fs`, `lunepack-http`, `lunepack-codec-lzma`, `lunepack-os-linux`, `lunepack-os-macos`, `lunepack-os-windows`). Every other member has `publish = false`. The binaries `lunepack-runtime`, `lunepack-service` and `lunepack-stub` are not published because their build options (static linking, the subsystem) live in `.cargo/config.toml`, which a package does not carry, so `cargo install` would build a different program; they ship as prebuilt files from the project's releases or are built from a checkout. The two UI crates are not published because LuneUI is a git dependency (D39). The testkit and `xtask` are repository tooling. The boundary check holds the set (`PUBLISH_SET`): a member of the set is publishable, any other member must say `publish = false` (so a new crate is unpublishable until it is added to the list), and no member of the set has a normal or build dependency on a member outside it or on a git source. `scripts/publish-dry-run.sh` packages the set with `cargo publish --workspace --dry-run` and fails unless exactly these ten reach the upload step; the tests of the packaged crates are left out of the packages.

## Dependency direction

Dependencies point inward only: an adapter depends on the core, never the reverse, and adapters
do not depend on each other. The facade and the binaries sit outside the adapters and may use
them. `dev-dependencies` may name `lunepack-testkit` and nothing else from the workspace.

## Traits

Owned by the core, implemented by adapters, faked in the testkit. Defined today:

- `Hasher` (one-shot and streaming SHA-256), implemented by `lunepack-crypto`;
- `Verifier` (`verify` with strict Ed25519 semantics, and the required `check_public_key` that
  rejects non-canonical and small-order keys), implemented by `lunepack-crypto`;
- `Clock` (`now_unix_secs`; the only source of time in the core);
- `Codec` (decodes one verified frame into a writer and reports the bytes consumed per stream; `decode_patch` decodes one verified patch against the base's bytes, M12);
- `Encoder` (encodes one file with a given codec id, and estimates the memory it needs; the producer
  side, so `Codec` stays decode-only, M3-D2; `encode_patch` and `encode_patch_memory` for a patch against a base, M12), implemented by `lunepack-codec-lzma`;
- `Signer` (an Ed25519 public key and a signature over a message), implemented by
  `lunepack-crypto`;
- `CodeSign` (the pipeline's OS code-signing hook, run on the assembled tree before hashing. Since M9 it
  takes the **sign plan** instead of a flat file list: `sign_plan(target, entries, main_exe)` in the core
  is a pure function from the tree's entries to the typed items to sign, inner to outer (Windows: every PE
  file without a certificate table; macOS: loose Mach-O files, nested bundles deepest first, then the
  bundle itself, the main executable excluded; Linux: nothing). `NoCodeSign` is the identity; `OsCodeSign`
  in `lunepack-cli` runs the developer's `ArgvTemplate`s, a core type with a closed grammar (placeholders
  only as whole arguments, `{env:NAME}` for non-secret values, no other brace), M9-D1 to M9-D5);
- `PublisherCheck` (C7, M9: `same_publisher(installed, candidate) -> Result<bool, PublisherError>`, whether
  two trees are signed by the same operating-system code-signing publisher, answered from a closed set
  of `PublisherError` codes and never from the network; the core's `decide(policy, result)` is the
  policy table that turns an answer into proceed, report or refuse, total over every pair). Implemented
  by `WinPublisherCheck`, `MacPublisherCheck` and `NoPublisherCheck`; the facade runs it between
  staging and recording the staged version (`docs/RUNTIME.md`, "Publisher continuity"). Fake:
  `FakePublisherCheck`; suite: `run_publisher_suite`, run by each adapter;
- `Transport` (async, object-safe: `get(Request) -> BoxFuture<Result<Response>>` with `Send + 'static`
  futures and a chunk-stream `Body`; a host app injects its own client, such as reqwest inside its
  runtime; the facade polls it on the caller's task, M4-D1, M4-D2). The contract every transport
  follows: follow redirects and return the final response, send `Range` and `If-Range` exactly as
  given, never send `Accept-Encoding`, never decode a content coding, report a missing resource as a
  `Head` with its status and every header lowercased with duplicates kept. The shared response rules
  live in the core, not in the adapters. Fake: `FakeTransport`; suite: `run_transport_suite`;
- `BlockingTransport` (the same contract, synchronous, with a `CancelToken`), implemented by
  `UreqTransport` and `DirSource`; the facade's `WorkerTransport` presents any of them as a
  `Transport`. Fake: `FakeBlockingTransport`; suite: `run_blocking_transport_suite`, run by
  `UreqTransport` against `LoopbackServer` (every case) and by `DirSource` against a temporary
  directory, with the cases a directory cannot offer switched off through `TransportCaps`
  (validators, duplicate headers, the request log, and the redirect off Unix), each named where it is
  switched off;
- `Fs` (capped reads, positional reads, create-new and append writes with sync, truncate, rename,
  removal, directory creation, listing and sync, copy, `set_exec`, `symlink`, `read_link`,
  `replace_symlink` and `symlink_metadata`, and `try_lock` returning a `LockGuard`; since M8 also
  `exchange` (atomically swap two directory names; `Unsupported` where the volume cannot), `place`
  (device, inode, volume type, read-only, owner and writability facts of one path, no link followed),
  `is_exec` and `create_dir_private`, each `Unsupported` by default so an adapter that lacks one fails
  closed), implemented by `lunepack-fs`. `replace_symlink` is the atomic flip of an install's `current` link: it makes a
  temporary link in the link's directory and renames it over the old one (two crash ops in
  `MemFs`), and refuses a file or directory at the link (M5 step 3). Fake: `MemFs` with crash
  injection; suite: `run_fs_suite`, run by `StdFs` and `MemFs`;
- `Rng` (`fill`, the only source of random bytes; a failure is `Error::Random`, never a weaker
  fallback), implemented by `lunepack-crypto`'s `OsRng` over `getrandom`. Fake: `FakeRng`, a seeded
  deterministic sequence; suite: `run_rng_suite`, run by `OsRng` and the fake;
- `Process` (the running executable and process id, the parent, `spawn_detached` and `spawn_child`
  without a shell (`spawn_child` with `ChildStdio::Piped` gives the parent the child's standard input and output, which only the UI channel uses, M6-D1; `spawn_detached` refuses it), `wait_exit` by pid and start time so a reused pid is not mistaken for the
  original, and `tree_in_use`; a `Child` is polled and terminated, only itself; since M8 also
  `spawn_app_background`, which starts an app without bringing it to the front where the OS has such a
  thing and by default is `spawn_child`, so its `Child` may report `ExitKind::Unknown` (the app has gone but
  its status is not observable, because it is not our child; the supervisor treats it as it treats a clean
  exit, so the health deadline decides)), implemented by `lunepack-os-linux` (M5 step 5), `lunepack-os-windows`
  and `lunepack-os-macos`. Fake: `FakeProcess` (records spawns, scripted exits, waits and
  in-use answers); suite: `run_process_suite`, which needs a helper executable the adapter's tests
  build. Errors name no path beyond a file name and no argument or environment value;
- `OsIntegration` (`check`, `apply`, `remove` of an app's desktop entry and command link, built
  from the update config's `InstallMeta` and the `stale_bins` of the outgoing version; `apply` and
  `remove` return an `IntegrationReport` naming what they left because it is not lunepack's;
  removal checks a marker; machine scope is `Unsupported` in the per-user adapters, and the system-wide entries of a per-machine install are written by `MachineIntegration` on Linux and `MacMachineIntegration` on macOS, M11-D12), implemented by
  `lunepack-os-linux` as `XdgIntegration` (M5 step 6): the desktop entry is ours when it carries
  `X-Lunepack-App-Id=<app id>`, the command link when its target lies under `<root>/current/`,
  and an unsafe path is refused, never escaped. On macOS (M8-D12) `MacIntegration` writes one LaunchAgent
  plist for `autostart` and nothing else; a file is its own when it is a regular file whose `Label` is the
  app's. Fake: `FakeIntegration` (records calls,
  scripted conflicts); suite: `run_integration_suite`, run on a sandbox directory.

The machine-install ports (M10, all object-safe and `Send + Sync`; each has a fake in the testkit and a contract
suite its adapter runs):

- `Protect` (`create_dir`, `check`: a directory created with an explicit protected descriptor of its
  `DirClass`, `MachineTree` or `AdminOnly`, and re-read to prove it is, FORMAT.md 18.2), implemented by
  `lunepack-os-windows`'s `WindowsProtect` and, by the unix rule of `lunepack_core::unix_protect` (M11-D7), `LinuxProtect` and `MacProtect`;
- `ServiceRegistrar` (`register`, `image`, `set_image`, `self_test`, `remove`: the operating system's
  registration of an app's update service, FORMAT.md 18.3), implemented by `WindowsRegistrar`, `SystemdRegistrar` (FORMAT.md 20.4) and `LaunchdRegistrar` (20.5);
- `ServiceConnector` (`connect(app) -> Box<dyn Duplex>`: a channel to the service with its owner checked) and the
  core's `Duplex` (a byte channel with a settable read deadline, the only thing the protocol sessions need),
  implemented by `WindowsConnector` over `PipeClient`; the server side is `PipeServer`; on Linux and macOS (M11) `UnixConnector`, which checks the socket's folder and owner and the peer's uid before a byte, with `ActivatedListener` on the server side;
- `PolicySource` (`read(app) -> MachinePolicy`, infallible: an unreadable value counts as on), implemented by
  `RegistryPolicy`, and on Linux and macOS (M11-D11) `FilePolicy`, a root-owned JSON file;
- `Elevation` (`standing`, `run_elevated`: the hand-off to an elevated child that may be declined), implemented
  by `WindowsElevation`, `PkexecElevation` on Linux and, on macOS, an elevation with no prompt of ours that reports the caller's standing and nothing to ask with (D38 (a)); `Standing` is `Standard`, `Admin` or `UacElevated`;
- `Process::tree_in_use_strict`, an added method with a default (`tree_in_use`, so macOS and Linux keep their
  scans) that every engine removal under a per-machine install asks before and after the rename that
  removes a path from new launches (M10-D20); the Windows adapter adds the file-system probe, and the Linux
  and macOS adapters scan every process of every user and count one they cannot read as in use (M11-D13).

`Clock` is implemented by `lunepack::SystemClock` and by the testkit's fake; the CLI adds a fixed
clock for `SOURCE_DATE_EPOCH`. Each trait has a contract suite in the testkit that the real
implementation's `tests/` runs, and a fake in the testkit. `LinuxProcess` and `XdgIntegration`
(M5 steps 5 and 6) run `run_process_suite` and `run_integration_suite`; the Windows adapters run the
same suites since M7 (the integration suite with hooks for the registry and the staged stub), and the macOS
adapters since M8 (`MacProcess` and `MacIntegration`; the `Fs` suite also covers `exchange`, `place` and
`is_exec`).

## Layouts and the current tree

The facade takes its locations from the app (M4-D4, amended): a `Layout` with the state, cache and
versions directories, and optionally an explicit current tree. Per-OS discovery comes with the
installers (Linux per user in M5, Windows per user in M7, macOS per user in M8). The rule they must place trees by:

- version `V`'s tree is `<versions dir>/<V's version text>`; `stage` builds it there, as
  `<V>.partial` renamed into place once every file is verified (M4-D18);
  `stage` refuses a version whose directory name differs from a kept version's only in letter case
  (one directory on a case-insensitive file system; FORMAT.md 12.7);
- the current tree is the layout's explicit `current_tree` when given (a layout whose live tree is
  not under the versions directory, such as an in-place bundle), else
  `<versions dir>/<current version text>`. It counts only when it is a real directory (a symlink is
  not followed); otherwise the scan finds no unchanged files and every file is fetched, which is
  correct and only slower;
- for a per-machine install the library only reads the machine tree through the same two fields and
  stages nothing itself: it uploads the documents it verified and the objects its cache holds to the
  install's update service, and the privileged engine verifies them again and builds the tree (C8, M10-D2);
  with neither field it scans nothing and downloads every frame into the user's cache.

The record does not hold a tree path: the layout is the one source (FORMAT.md 12.7).

### The Linux per-user layout (M5-D2, M5-D17)

An installed app's root `R` is `<data home>/<app id>` (the data home is `$XDG_DATA_HOME` when it is
set, absolute and UTF-8, else `$HOME/.local/share`):

- `R/versions/<ver>/`: one tree per version, with `lunepack-update.json` at its root (FORMAT.md 13),
  the app's entry wherever that configuration says and `lunepack-runtime` in the entry's directory;
- `R/state/` (the install-state records and `lock`), `R/cache/`, `R/logs/runtime.log`;
- `R/current`: a relative symlink to `versions/<current>`, derived from the record and never read as
  truth; every start and apply reconciles it. A flip is one atomic symlink replacement;
- outside `R`: the desktop entry and the command link `~/.local/bin/<bin>`, both pointing through
  `R/current`, so a flip needs no rewrite there.

An executable finds its own tree by walking up from its resolved path to the nearest
`lunepack-update.json`; the tree is installed when it is `R/versions/<its version>` with a record of
the same app id at `R/state`. A tree anywhere else is a bootstrap (or a development run).

### The layout scheme (M7)

One value in the core, `LayoutScheme`, names everything an OS's layout decides, so the same code serves both:
how `R` is named (`RootNaming::AppId` or `DisplayName`), the names of the versions, state, cache and logs
directories (each possibly several components), and whether a `current` link is projected
(`Projection`). `LayoutScheme::XDG` is the Linux layout above. `LayoutScheme::WINDOWS` is `R` named after the
display name, `app`, `.lunepack/state`, `.lunepack/cache`, `.lunepack/logs` and no link. `LayoutScheme::MACOS`
(M8-D1) has XDG's names and projects the record as a bundle (`Projection::Bundle`) instead of as a `current`
link, with the config at `Contents/Resources/lunepack-update.json`. A composition root
picks the scheme with the platform adapters (`Platform::layout_scheme`, in the facade and the runtime);
nothing in the core knows which OS it runs on (the core has no `cfg`). `resolve_root` finds an install of an
app id under a data home (for the Windows scheme by reading the records of the data home's folders, read
only; for the XDG scheme it is the path `<data home>/<app id>` with no listing) and chooses the folder of a
first install; `root_valid_for_uninstall` is the uninstall's check of the root its own path names;
`windows_name_ok` is the display-name rule (`docs/FORMAT.md` 13.4); `launch_target` is the stub's read path
(`docs/FORMAT.md` 15).

### The Windows per-user layout (M7-D2, M7-D16)

`R` is a folder of the per-user programs folder (`FOLDERID_UserProgramFiles`, by default
`%LOCALAPPDATA%\Programs`) named after the app's display name at its first install and found by the install
record afterwards, so a later display name does not move the install. Inside it: the stub at
`R\<entry file name>`, `app\<version>\` (one tree per version, the same contents as on Linux), and a hidden
`.lunepack\` holding `state`, `cache` and `logs`. There is no `current` link (Windows symlinks need a
privilege): the stub and the runtime read the install record for the current version. The runtime starts
from `R\app\<version>\` and finds `R` from its own path as on Linux. `docs/FORMAT.md` 16 states the layout
as a cross-version contract, and `docs/RUNTIME.md` ("Windows") what an app has to know.

### The Windows per-machine layout (M10-D8, M10-D9)

`R = <Program Files>\<display name>` from the known-folder API, with the version trees in `app\<version>`, the
machine record in `.lunepack\state` (world-readable) and an admin-only `.lunepack\machine` holding the engine's
lock, the upload staging (`incoming\`) and the service binaries (`service\<version>\`). Every directory the
engine creates gets an explicit protected descriptor, and the engine checks the five top ones at the start of
every operation. Each user keeps their counters, cache and logs in `<LocalAppData>\lunepack\<app id>\`, a
cross-version location. The files and descriptors are FORMAT.md 18; the service protocol is FORMAT.md 19.

### The Linux and macOS per-machine layout (M11-D6, M11-D7, M11-D10)

One set of names on every OS and three projections: `R` is `/opt/<app id>` on Linux and
`/Library/Application Support/lunepack/<app id>` on macOS, with `app/<version>`, the machine record in
`.lunepack/state`, `.lunepack/logs` and an admin-only `.lunepack/machine` that holds the lock, `incoming/`, the
service binaries in `service/<version>/` and the **stable service link** `lunepack-service`, which the init system
starts and which an atomic rename switches. The engine projects the committed record after every commit: the link
`R/current` on Linux, the bundle swap of FORMAT.md 17 on macOS (the live bundle in `/Applications`). Every directory
is created with an exact owner and mode and checked, together with every ancestor of `R`, by the unix rule. Each
user keeps their counters, cache and logs in `<data home>/.lunepack/<app id>/`, a cross-version location. The
files, the units, the property list and the policy files are FORMAT.md 20; the transport is FORMAT.md 19.8.

### The macOS per-user layout and the bundle projection (M8-D1 to M8-D5, M8-D16, M8-D17)

`R` is `<data home>/<app id>` under the canonical `~/Library/Application Support`, with `versions/<version>/`,
`state/`, `cache/` and `logs/` as on Linux. The live app is not in `R`: it is a bundle `B` in `~/Applications`
that `R/bundle` points at (an absolute, canonical symlink), with `R/bundle.id` holding its device and inode.
`docs/FORMAT.md` 17 states the layout as a cross-version contract and `docs/RUNTIME.md` ("macOS") what an app
has to know. The pieces:

- **The record is the truth, reconcile only renames.** `UserLayout::reconcile` under `Projection::Bundle`
  (`reconcile_bundle`) makes `B` hold `record.current` by renaming trees through two slots in `R/versions`,
  `.swap` and `.out`, with `Fs::exchange` when the volume supports it and the journaled two-rename when it
  does not. It identifies every tree by the app id and version in its own configuration, follows nothing at
  `B`, a slot or a version path, and never deletes, copies or writes (but for `R/bundle.id`). Exactly one
  thing deletes a version tree, garbage collection over `R/versions`, and an uninstall deletes `B` and `R`
  (M8-D5). Crash tests enumerate a cut after every mutating call, on both paths, for an apply, a rollback and
  the first placement, and require the same end state and a no-op second reconcile.
- **Discovery** (`discover_bundle`) returns where a running bundle stands: refused for its location
  (translocated, read-only), installed (the pointer names it, or it is an old instance in `R/versions`),
  a moved bundle to follow (its device and inode are recorded), adoptable (in an apps folder, with no live
  install) or not installed. `check_place` judges `B` before anything is changed (other volume, not owned,
  not writable). All of it reads through `Fs`, so it runs on `MemFs` with crash injection, and the same code
  runs on the real disk in the runtime's tests.
- **Orphaned and replaced installs** (M8-D16) are decided from the record and the trees alone;
  `reinstall_orphaned` (and the facade's reset before an install) keeps only the anti-rollback floors.
- **Adoption** (M8-D9) is a core `verify_tree` (a bundle equals its signed manifest: paths as listed bytes,
  sizes, hashes, exec bits and link targets, no extra entry, nothing followed) and the facade's commit order,
  `R/bundle.id`, the integration, the record, `R/bundle` (`docs/FORMAT.md` 17.5).
- **Names.** `macos_name_ok` is the bundle-name rule (the packager and setup call it too), and
  `resolve_bundle_target` chooses `B` at a first install (`<name>.app`, else `<name> (<app id>).app`, else a
  refusal).

## The installer UI (M6)

Install, update and uninstall show their screens in a separate process, `lunepack-ui`, built on
LuneUI (D35, D39). The engine (the runtime, in its install, uninstall, apply and setup modes) decides
everything and does every file and process operation; the UI renders what the engine tells it and
returns choices, and its failure never changes an outcome (M6-D5). No elevated or privileged process,
and none of the runtime, the stub or the `lunepack` facade, links or initialises a GPU or window stack
(D17); the boundary rules above enforce it.

- **The port** is `lunepack_core::ui`: `EngineMsg` (hello with the flow, the app card and the install
  details; progress; steps; prompts; the outcome; `Ping`; `Close`) and `UiMsg` (hello, choices,
  `Pong`), the frame codec (`write_frame`, `read_frame`: M6-D2), the build id (`build_id`,
  `check_hello`) and the reducers. `FlowState` is the engine's model of the conversation: it says which
  engine message is valid next (`apply`) and whether a message from the UI is acceptable now
  (`accepts`: a choice must answer the open prompt's id with a value of that prompt's set; `Pong` the
  latest `Ping`). Every choice goes through it before anything acts on it.
- **The channel** is the UI's standard input (engine to UI) and standard output (UI to engine), as
  pipes created at spawn (M6-D1); its error stream is null. Frames are a little-endian `u32` length and
  a strict JSON body of at most 1 MiB. The UI says hello first with its build id, and the engine
  refuses a different one: UI and engine are from one build (D28), so the protocol carries no
  cross-version promise.
- **The host** is `lunepack-runtime`'s `UiHost`. It starts the UI only from the directory of the
  runtime's own resolved path, never through `PATH`, `current` or a link (a setup file's UI comes from
  its private directory, M6-D7), and not at all under `--silent` or `--no-ui`, with `LUNEPACK_NO_UI`,
  with no display, or with no UI binary. Three threads belong to it and none is ever joined without a
  bound: the writer (the only thread that writes to the UI, fed by a bounded channel, so the
  operation never waits for a UI), the reader (checks each frame against the reducer) and the
  watchdog. A frame that does not fit, a write in progress for more than 2 s, no hello within 20 s,
  no `Pong` within 15 s of a `Ping` (sent when a question opens and every 5 s after), a protocol
  error or an exit stops the UI: the host kills its own child, goes headless, and logs one
  `ui_stopped` warning with a reason from a closed set (`docs/RUNTIME.md`).
- **Exit codes** of `lunepack-ui`: 0 closed, 10 no display, 11 no adapter, 12 protocol error, 13 engine
  gone, 14 build-id mismatch, 2 usage. The host maps 12 to `protocol` and 14 to `build_mismatch`; any
  other exit is `exited` with the code logged beside it.
- **Headless** is the default of every question (proceed, do not launch, close, acknowledge), so a
  machine with no display, no adapter or no UI binary installs and updates as before (D36, D41).
- **Tests.** The host runs against a fake UI in `crates/lunepack-runtime/tests/ui_host.rs` (a UI that
  never speaks, stops reading, hangs, exits at each typed code, sends garbage, is killed); the screens
  are checked by headless golden frames (one set per OS, M6-D9), an accessibility tree replay and a
  keyboard script per prompt in `lunepack-ui-luneui`; the real binary by a smoke test against a
  scripted engine in `lunepack-ui`; these run on developers' machines, not in CI (M6-D13); and the Linux end-to-end suite installs through a setup file with
  a stand-in UI that speaks the protocol with no window, with the UI killed and with none.

## Composition roots

Nothing constructs an adapter except a composition root: the `lunepack` facade for embedding
apps, and `main.rs` of each shipped binary (`lunepack-runtime`, `lunepack-cli`, and, since M10, the
update service `lunepack-service`, which wires the privileged engine's ports and nothing else). Adding a codec, platform or binding means adding a
crate and one registration line in a root; the core does not change.

## How the boundary check enforces this

`./scripts/check-boundaries.sh` runs `xtask check-boundaries`. Dependencies, sources and package
fields come from `cargo metadata` (cargo is the authority on what a manifest declares); only the
`[lints]` tables and the root `[workspace]` keys are read with a real TOML parser. Anything the
check does not recognise is a violation, and an internal error exits 2, never 0. It rejects:

- a dependency that breaks the table above, including renamed, optional, target-specific and
  build dependencies (identified by package name), git dependencies, path dependencies outside
  the workspace, and external crates in the core that are not allowlisted;
- a workspace member it has no role for, and any member under `probes/` or `fuzz/` (both stay
  outside the workspace; when `fuzz/Cargo.toml` exists the root `exclude` must name `fuzz`);
- a crate without `[lints] workspace = true`, except the allowlisted crates (`lunepack-fs`, the
  `lunepack-os-*` crates, later the FFI crate), which may replace the table with a full copy whose
  only differences are `unsafe_code` and an added `undocumented_unsafe_blocks = "deny"`;
- a root `unsafe_code` that is not `forbid`, and package fields (edition, license, MSRV) that
  differ from the workspace's.
- a `Cargo.lock` (the workspace's and each `probes/*/`'s) that is missing, or has a package that is
  neither from crates.io nor, without a source, one of that lock's own members by name and version
  (the workspace members, or the probe's own package); this catches git and other-registry sources
  and path dependencies, including those redirected by `[patch]`, `[replace]` or a
  `.cargo/config.toml` patch, because the lock records what cargo actually resolved. The one
  exception is the workspace lock's LuneUI source (D39 (b), below). A `[patch]` or
  `[replace]` section in the root or a probe manifest is flagged too. The check does not read
  `.cargo/config.toml` itself; it sees a config patch only through the lock it produced.
- `fuzz/` (M2-D9): its `Cargo.lock` is held to the same rule, with the workspace's members (by name
  and version) and the fuzz package itself as the only source-less entries, and a missing
  `fuzz/Cargo.lock` is a violation. Its manifest's dependencies (normal, dev, build and
  target-specific) must be crates.io requirements or `path` dependencies on a workspace member
  (same package name, same directory); a `git`, `registry` or `workspace` key, any other path and
  any form the check does not recognise is a violation.
- confined crates (M3-D11, `CONFINED` in `xtask/src/boundaries.rs`): `lzma-rust2` may be named only
  by `lunepack-codec-lzma`. No other workspace package may depend on it in any kind, target or
  rename (matched on the package name `cargo metadata` reports); in every lock the check reads
  (the workspace's, `probes/*/`, `fuzz/`), any `[[package]]` whose `dependencies` names it must be
  `lunepack-codec-lzma` as a source-less member, which catches pulls through third-party crates;
  an unparseable `dependencies` value is a violation. The codec crate's requirement must be exactly
  `=0.25.0` (`EXACT_PINS`).

- the HTTP stack's crypto provider (M4-D16, `REACH_ONLY_THROUGH` and `FORBIDDEN_ANYWHERE` in
  `xtask/src/boundaries.rs`). Over the graph in each lock the check already reads (the
  workspace's and `fuzz/`'s; `[[package]]` entries and their `dependencies` strings, so every
  platform and dev edge, offline): the walk from each workspace member must not reach `ring`
  except by entering `lunepack-http`, and a violation names one shortest path. Packages named
  exactly `aws-lc-rs`, `aws-lc-sys`, `openssl` or `openssl-sys` may appear in no such lock (an exact
  match, so `openssl-probe` is allowed). An edge that matches no entry or several, or a
  `dependencies` value that is not an array of strings, is a violation too, because the graph
  cannot be trusted. Probe locks are exempt: they are throwaway and outside the workspace.

- LuneUI and its GPU and window stack (M6; D17, D39 (b)):
  - the only git source is `https://github.com/lune-rs/luneui-rs` at one exact commit, set by
    `LUNEUI_GIT_URL` and `LUNEUI_REV`. A dependency on any of LuneUI's own packages (`LUNEUI_CRATES`)
    must carry exactly that source as `cargo metadata` reports it, so another URL, another commit,
    a `branch` or a `tag`, or no `rev`, is a violation. In the workspace lock only that exact source
    string (with the same commit after `#`) may be a git source, only LuneUI's own packages may come
    from it, and they may come from nowhere else. Probe and fuzz locks get no such exception;
  - `lune-ui` is confined (`CONFINED`) to `lunepack-ui-luneui`, and `lunepack-ui-luneui` is a
    dependency of `lunepack-ui` alone, `lunepack-ui` of nothing (`ONLY_DEPENDED_ON_BY`; any kind,
    and the fuzz project's path dependencies too);
  - `lune-ui*`, `wgpu*`, `winit*` and `accesskit*` (a family is the name, or the name continued
    with `-` or `_`) are reachable only through `lunepack-ui-luneui`
    (`REACH_FAMILIES_ONLY_THROUGH`, the walk of M4-D16 over the lock graph). So the only crates
    whose dependency closure holds `wgpu` or `winit` are `lunepack-ui-luneui` and `lunepack-ui`.

- the Windows stack (M7): the `windows` crate (the COM interfaces of the shortcut) is reachable only through
  `lunepack-os-windows` and `lunepack-ui-luneui` (`REACH_ONLY_THROUGH`, which takes several allowed crates
  and matches by exact package name, so `windows-sys` and `windows-core` are other packages); `editpe` is
  confined to `lunepack-cli` and pinned `=0.2.4` with `default-features = false` (`CONFINED`, `EXACT_PINS`;
  its one `unsafe` block is accepted by D17); and `lunepack-stub` may depend only on the core, the
  filesystem adapter, `lunepack-crypto` and `lunepack-os-windows` (`DEPENDS_ONLY_ON`, normal and build
  dependencies; a dev-dependency or another binary is not held), so no network, codec or UI code reaches the
  launcher whose contract is frozen.

- the update service (M10-D7, M11): `lunepack-service` may depend only on the core, `lunepack-fs`,
  `lunepack-crypto`, `lunepack-codec-lzma` and the three OS adapters, `lunepack-os-windows`,
  `lunepack-os-linux` and `lunepack-os-macos` (`DEPENDS_ONLY_ON`, normal and build dependencies), so no HTTP,
  TLS, UI or facade code runs in the LocalSystem or root process that any local user feeds.

- the macOS code-signing stack (M9-D10): `security-framework` is reachable only through `lunepack-http`
  (it already reaches it through the HTTP stack's platform verifier) and `lunepack-os-macos`
  (`REACH_ONLY_THROUGH`), so the publisher check's FFI is the only other consumer.

Adding a crate is one line in `ROLES` in `xtask/src/boundaries.rs`.

## Fuzzing

`fuzz/` is a cargo-fuzz project outside the workspace, with its own committed `Cargo.lock` and one
target per harness of `lunepack_core::fuzz` (`envelope`, `root`, `keys`, `feed`, `manifest`,
`path`, `tree`, `rules`, `json`, `frame`, and since M4 `http`, the response-header and `Content-Range`
rules, and `state`, the install-state record reader). `fuzz/seeds/<harness>/` holds committed seeds written by
the real writers (`lunepack_testkit::fuzz_seeds`); `corpus/`, `artifacts/` and `target/` are
gitignored. The gate does not run libFuzzer (it needs nightly and a C++ build). It runs
`crates/lunepack-testkit/tests/fuzz_replay.rs` on stable: the committed seeds must equal what the
writers produce, every seed must behave as named, and random and mutated inputs must not panic.
Since M13 the same project has twenty targets (the harnesses above plus `deltas`, `update_config`, `setup`,
`service`, `ui`, `prebuilt`, and the real-decoder targets `codec` and `patch` of `lunepack_codec_lzma::fuzz`),
and libFuzzer runs them: `scripts/fuzz.sh` in a pinned Docker image, and `.github/workflows/weekly.yml` on a
schedule, which also runs `cargo deny`. `docs/THREAT-MODEL.md` ("Fuzz coverage") has the table of what each
target covers and what the first runs found. `fuzz/README.md` has the commands.

## Releasing (M13)

`.github/workflows/release.yml` is one workflow in five modes (`dry-run`, `binaries`, `rehearsal`, `tag`,
`rehearsal-finalize`), decided by `scripts/release/mode.sh`, the only reader of the event, the ref and the
input. It builds the prebuilt binaries (`scripts/release/build.sh`, `build.ps1`), assembles the list of them
(`assemble.sh`, a FORMAT.md section 21 document), signs it in the one job `sign` that can read the project
key (`sign-list.sh`, which runs `lunepack prebuilt sign`), and, at the tag, proves the pins
(`verify-pins.sh`) before it adds the CLI and publishes. `pin.sh` makes the pin commit, and
`check-signing-env.sh` checks the signing environment's settings. `scripts/tests/test-workflows.sh` holds the
workflows to their rules and `scripts/tests/test-release-scripts.sh` runs the scripts on fixtures. On the CLI
side, `crates/lunepack-cli/src/project_key.rs` holds the project's public key sets (empty until the key
ceremony), `prebuilt.json` and `prebuilt.sig.json` the list and its envelope for the CLI's own version, and
the commands `prebuilt list`, `check`, `sign`, `verify` and `fetch` read them (`docs/CLI.md`); the state
function that decides what is pinned has one caller that passes the compiled-in constants. The runbook is
`docs/RELEASING.md`; what the key is worth is in `docs/THREAT-MODEL.md`. `examples/dotnet` is an app in
another language that updates itself through the runtime's command line, and `scripts/publish-dry-run.sh`
packages the ten crates of the publish set without uploading.

## Probes

`probes/` holds throwaway platform probes: scripts and two small standalone crates, outside the
Cargo workspace and never published. They run only on GitHub-hosted runners
(`.github/workflows/probes.yml`), each with a control that decides whether its verdict counts.
