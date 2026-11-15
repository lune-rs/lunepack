# Architecture

How the workspace is split and how the split is enforced. Crate roles and the boundary rules
are the current design; thirteen traits are defined (below). The wire
format is `docs/FORMAT.md` and its threat model `docs/THREAT-MODEL.md`. Decisions behind this are in
`docs/DECISIONS.md` (D1, D6, D14, D17, D23, D26, D28, D30, D31, D33, M2-D1 to M2-D9, M3-D1 to M3-D13,
M4-D1 to M4-D23, M5-D2 to M5-D17).

## Crates

| Crate | Role | May depend on |
|---|---|---|
| `lunepack-core` | Types, rules, verification policy, planning, state machine, apply engine; owns every trait and the error enum. No I/O, clock, randomness or network of its own. Today: strict JSON, DSSE envelopes, root rotation, key sets, feeds, manifests, frame descriptors, the path, version and target rules, update policy, and the hidden `fuzz` harness module. Since M4 also the sans-IO client logic: the transport traits and the pure HTTP response rules (`Content-Range`, validators, encoding, fetch planning), the `Fs` trait, the install-state store (records, commit and load, scopes, transitions; FORMAT.md 12), the stage engine (scan for unchanged files, bounded parallel decode within a memory budget, resume, `NeedFetch`), the `CancelToken` and the progress event types. The one use of threads in the core is `std::thread::scope` (and `std::thread::panicking`) in the stage engine, because the worker count comes from the caller, so the output never depends on the machine; it uses no clock, environment, filesystem or network, the purity test allows exactly those two paths in `stage.rs`, and any other thread use in the core stays forbidden (M4-D12, user decision Q30, 2026-11-14). | nothing external beyond an explicit allowlist: `serde`, `serde_json`, `base64`, `semver`, `unicode-normalization`, `thiserror` (M2-D1) |
| `lunepack-testkit` | In-memory fakes and the contract suites. Today: a fake clock, hasher, signature scheme and codec (with fault knobs), the contract suites for the traits below, document builders over the core's real writer, and the fuzz seed writer; `MemFs`, an in-memory `Fs` that injects a crash at any operation and recovers under a chosen durability mode; `FakeTransport` and `FakeBlockingTransport` over a `FakeOrigin` (Range, `If-Range`, validators, redirects, a request log and fault knobs such as an ignored Range, a wrong `Content-Range`, a truncated, endless or one-byte-chunk body); and `LoopbackServer`, the same origin over a real `127.0.0.1` socket; and, since M5 step 3, `FakeRng`, `FakeProcess` and `FakeIntegration` with their suites. `publish = false`. | core |
| `lunepack-crypto` | Hashing and signature verification adapters: SHA-256 and Ed25519 with strict verification; and the signers (M3): `Ed25519Signer` over PKCS#8 PEM from a file or an environment variable, `generate_key_file`, and `CommandSigner` (an external command whose signature is verified before use). Nothing it prints or returns in an error holds key material. | core |
| `lunepack-codec-lzma` | Compression adapter over `lzma-rust2` (confined to this crate, M3-D11): the `Codec` decoder with limits from the signed descriptor, and the `Encoder` at the 9e settings for all five codec ids (stored, LZMA2, BCJ x86 and ARM64 + LZMA2, BCJ2). Delta coding comes later. | core |
| `lunepack-fs` | Filesystem adapter: `StdFs`, the `Fs` implementation over `std::fs` (it refuses symlink components when it creates directories, and syncs files and directories), and the OS lock behind `Fs::try_lock` through `fs4` (released by the OS when its holder dies). May lift `unsafe_code`; documents that Windows directory durability is an unverified assumption. | core |
| `lunepack-http` | Release source and network adapter: `UreqTransport`, the default `BlockingTransport` (ureq 3.5 with the OS platform verifier for TLS and the system proxy: environment first, then WinINET on Windows and the system proxy through hyper-util on macOS; no content decoding, `User-Agent: lunepack` only) and `DirSource`, which serves `file:` URLs under one root with Range support. The only crate that reaches `ring` (below). It also holds an `os_trust` example that CI runs through the real adapter. | core |
| `lunepack-os-windows`, `lunepack-os-macos` | OS install, shortcut, autostart and process adapters (empty until M7 and M8). | core |
| `lunepack-os-linux` | The Linux adapters (M5): `LinuxProcess` implements `Process` over `/proc` and `libc` (spawn without a shell, detach, wait by pid and start time so a reused pid is not mistaken for the original, terminate only its own child, the in-use scan of a tree), and `XdgIntegration` implements `OsIntegration` (the desktop entry `<data home>/applications/<app id>.desktop` built fail-closed from the update configuration, the command link in `~/.local/bin`, removal checked by a marker). One of the crates that may lift `unsafe_code`, each block with a `// SAFETY:` comment. | core |
| `lunepack` | The app-facing facade and the composition root for apps that embed lunepack: `UpdaterBuilder` wires the default adapters (`WorkerTransport` over `UreqTransport` for `http(s)`, `DirSource` for `file:`, `StdFs`, the LZMA codec, SHA-256 and Ed25519 from `lunepack-crypto`, `SystemClock`), each swappable. `Updater` offers `check`, `download`, `stage` as `Send + 'static` futures that need no particular executor, the synchronous `installed` and `staged`, and `lunepack::blocking` for apps without a runtime. Under it, std-only task plumbing (worker jobs, bounded pipes, a built-in `block_on`, `WorkerTransport` that runs any `BlockingTransport` on worker threads, progress coalescing) and the fetch engine (documents, feed URLs, the cache, Range runs, pack resume, the full-pack fallback) (M4-D1 to M4-D3). Also `SystemClock` (M3-D5), the only wall-clock `Clock`. Since M5 it also finds an installed app from its own executable (`Installation`, which reads the update configuration of the tree and derives the install root `R`) and offers the lifecycle calls over the core's transitions: `startup`, `confirm_healthy`, `apply_and_restart` and `Updater::install` (M5-D2 to M5-D8); it wires the Linux process and integration adapters in `Platform::native`. | core, adapters |
| `lunepack-runtime` | Binary, static musl on Linux, one per version tree and placed beside the app's entry by the packager (D28, M5-D7). Its composition root (`main.rs`) wires the Linux adapters and runs a mode named on its command line: `apply` (started detached by `apply_and_restart`: wait for the app to exit, commit the staged version, flip `current`, start it with a health token, supervise it, roll it back if it fails or does not confirm in time, then collect old trees), `install` (the first install from a bootstrap tree) and `uninstall`. Progress and results are schema-1 JSON events on its log (`R/logs/runtime.log`) or stderr; every outcome has a stable exit code. It does its work through the facade, which is also what the app-facing command line of D42 will be (a thin layer over the same calls). Service and UI are later milestones. | core, adapters, facade |
| `lunepack-cli` | Binary `lunepack` and the packager's composition root: `init`, `keys`, `pack`, `feed add` and `refresh`, `verify` and `inspect` (`docs/CLI.md`). It holds the I/O the core must not have: `lunepack.toml`, signer specs, the release-directory walk, the pack pipeline (assemble a temporary copy, code-sign, hash, pack on a worker pool within a memory budget, sign), self-verification of every output with the core verifiers, and placement by temp file and rename. Pure rules (codec choice, layout, manifest, signing, document writers) stay in the core (M3-D1). | core, adapters, facade |
| `xtask` | Repository tooling: the boundary check, the key-container file check and the optional denylist scan. | nothing in the workspace |

A language binding (a C ABI crate, later others) is one more adapter crate over the core and adds no logic.
Every crate has `publish = false` until a publishing decision is made.

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
- `Codec` (decodes one verified frame into a writer and reports the bytes consumed per stream);
- `Encoder` (encodes one file with a given codec id, and estimates the memory it needs; the producer
  side, so `Codec` stays decode-only, M3-D2), implemented by `lunepack-codec-lzma`;
- `Signer` (an Ed25519 public key and a signature over a message), implemented by
  `lunepack-crypto`;
- `CodeSign` (the pipeline's OS code-signing hook, run on the assembled tree before hashing; the
  identity in the CLI's composition root until the OS adapters provide real ones);
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
  `replace_symlink` and `symlink_metadata`, and `try_lock` returning a `LockGuard`), implemented by
  `lunepack-fs`. `replace_symlink` is the atomic flip of an install's `current` link: it makes a
  temporary link in the link's directory and renames it over the old one (two crash ops in
  `MemFs`), and refuses a file or directory at the link (M5 step 3). Fake: `MemFs` with crash
  injection; suite: `run_fs_suite`, run by `StdFs` and `MemFs`;
- `Rng` (`fill`, the only source of random bytes; a failure is `Error::Random`, never a weaker
  fallback), implemented by `lunepack-crypto`'s `OsRng` over `getrandom`. Fake: `FakeRng`, a seeded
  deterministic sequence; suite: `run_rng_suite`, run by `OsRng` and the fake;
- `Process` (the running executable and process id, the parent, `spawn_detached` and `spawn_child`
  without a shell, `wait_exit` by pid and start time so a reused pid is not mistaken for the
  original, and `tree_in_use`; a `Child` is polled and terminated, only itself), implemented by
  `lunepack-os-linux` (M5 step 5). Fake: `FakeProcess` (records spawns, scripted exits, waits and
  in-use answers); suite: `run_process_suite`, which needs a helper executable the adapter's tests
  build. Errors name no path beyond a file name and no argument or environment value;
- `OsIntegration` (`check`, `apply`, `remove` of an app's desktop entry and command link, built
  from the update config's `InstallMeta` and the `stale_bins` of the outgoing version; `apply` and
  `remove` return an `IntegrationReport` naming what they left because it is not lunepack's;
  removal checks a marker; machine scope is `Unsupported` in M5), implemented by
  `lunepack-os-linux` as `XdgIntegration` (M5 step 6): the desktop entry is ours when it carries
  `X-Lunepack-App-Id=<app id>`, the command link when its target lies under `<root>/current/`,
  and an unsafe path is refused, never escaped. Fake: `FakeIntegration` (records calls,
  scripted conflicts); suite: `run_integration_suite`, run on a sandbox directory.

`Clock` is implemented by `lunepack::SystemClock` and by the testkit's fake; the CLI adds a fixed
clock for `SOURCE_DATE_EPOCH`. Each trait has a contract suite in the testkit that the real
implementation's `tests/` runs, and a fake in the testkit. `LinuxProcess` and `XdgIntegration`
(M5 steps 5 and 6) run `run_process_suite` and `run_integration_suite`; the Windows and macOS
implementations come with M7 and M8.

## Layouts and the current tree

The facade takes its locations from the app (M4-D4, amended): a `Layout` with the state, cache and
versions directories, and optionally an explicit current tree. Per-OS discovery comes with the
installers (Linux per user in M5, Windows in M7, macOS in M8). The rule they must place trees by:

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
  never stages (staging is the privileged engine's, C8); with neither field it scans nothing and
  downloads every frame into the user's cache.

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

## Composition roots

Nothing constructs an adapter except a composition root: the `lunepack` facade for embedding
apps, and `main.rs` of each shipped binary. Adding a codec, platform or binding means adding a
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
  `.cargo/config.toml` patch, because the lock records what cargo actually resolved. A `[patch]` or
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
The libFuzzer runs themselves are not done yet (CI, M13); the targets are only known to compile.
`fuzz/README.md` has the commands.

## Probes

`probes/` holds throwaway platform probes: scripts and two small standalone crates, outside the
Cargo workspace and never published. They run only on GitHub-hosted runners
(`.github/workflows/probes.yml`), each with a control that decides whether its verdict counts.
