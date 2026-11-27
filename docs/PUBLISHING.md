# Publishing your app and its updates

How an app that uses lunepack ships its first release and every update after it. The same steps do both:
a first release is a publish into an empty feed, an update is a publish into a feed that already has
releases. The flow is built into the CLI as `lunepack publish` ([`docs/CLI.md`](CLI.md) is the reference);
this page is the recommended way to run it, written so that a coding agent working on an app's repository
can follow it step by step. (lunepack's own release is a different runbook:
[`docs/RELEASING.md`](RELEASING.md).)

What it gives you: one flow for every app, to any S3-compatible store (Cloudflare R2 first), that uploads in
the order a client needs, keeps the newest releases and removes the rest, keeps the feeds from expiring,
and can be re-run safely after a failure. It changes no client format: a client reads the same signed
feed, manifests and packs, from whatever serves the public bucket.

## Ship a new version

For an app that is already set up (one-time setup is below). Do these in order.

1. **Bump the version** wherever the app keeps it (a version is SemVer 2.0.0: `1.4.0`, `1.5.0-rc.1`). Commit
   it. A version is published once; never reuse one, even after a failure, unless "Rerun and recovery"
   below says to.
2. **Tag the commit** `v<version>` and push the tag (`git tag v1.4.0 && git push origin v1.4.0`). The tag
   starts the publish workflow. Its commit's time becomes `SOURCE_DATE_EPOCH` for the pack jobs, so the
   same commit always packs to the same bytes.
3. **What runs**, in order: `tools-<os>` (builds the `lunepack` CLI once per OS and publishes its
   SHA-256; no secret) and `build` (your app, per target; no secret) → `pack` (per target: checks the CLI
   against that SHA-256, then `publish fetch`, `pack`, `setup`; the release key only) → `push` (checks the
   CLI, then `publish push --dry-run` and `publish push`; the release key and the push token, behind the
   owner's approval). A scheduled `refresh` keeps the feeds from expiring.
4. **Check the result** without any credential. Fetch the public state into an empty directory and look at
   the version folders it brings (the newest earlier releases, as delta bases):

   ```sh
   lunepack publish fetch --release-dir /tmp/published-check --version 999999.0.0
   ls /tmp/published-check
   ```

   `fetch` checks signatures and the chain: it verifies `keys.json`, the roots and every feed it finds
   under the app's root, and the manifests and packs of the delta bases. It does **not** check expiry (it
   reads with the time checks skipped, so that an expired feed can still be refreshed), so exit 0 does not
   show that the feeds are fresh. A feed that has expired is one clients refuse. Freshness is checked by
   `push` and `refresh` at the real time, and by clients; the owner sees each feed's expiry with
   `lunepack publish plan` (it needs the store credentials, so an agent does not run it against a real
   store). An agent that must know a feed is fresh asks the owner, or checks that the last scheduled
   `refresh` run succeeded.
5. **If a job fails**, read its first error line and find it in "When something is refused" below. Re-run
   only the failed job; do not delete anything in the store by hand and do not bump the version. A failed
   `push` job is re-run as it is: its inputs are the artifacts of the `pack` jobs, which do not change.

## One-time setup

This is the owner's work, done once per app, on the owner's machine. An agent does not do it and does not
touch the keys it makes ("Rules for agents").

1. **Make the keys** and write `lunepack.toml`: `lunepack init`, `lunepack keys gen`, `lunepack keys set`
   ([`docs/KEY-CEREMONY.md`](KEY-CEREMONY.md)). The root key stays offline. The release key goes into the
   secret `EXAMPLE_RELEASE_KEY` (a PKCS#8 PEM; `--sign env:EXAMPLE_RELEASE_KEY` reads it) of the CI
   environments of step 6, never a repository secret. Commit `lunepack.toml` (it holds public keys and
   names, never a secret).
2. **Make two buckets** in the store: a public one that a CDN or the store's public URL serves at
   `[update] feed`, and a private one (not served). The public bucket holds everything a client reads; the
   private one holds the publisher's state file and the pending-deletes record.
3. **Make three store API tokens**, with no bucket administration. On Cloudflare R2 make each in the
   dashboard: a dashboard token has one permission ("Object Read & Write" or "Object Read only") for the
   buckets it names, which is why the refresh job gets two.

   | Token | Permission | Buckets | Held by | Read through |
   | --- | --- | --- | --- | --- |
   | push | Object Read & Write | both | the `push` job only | both pairs of variables |
   | refresh-public | Object Read & Write | the public one only | the scheduled `refresh` job only | `access_key_env`, `secret_key_env` |
   | refresh-private | Object Read only | the private one only | the scheduled `refresh` job only | `private_access_key_env`, `private_secret_key_env` |

   `[publish]` names two pairs of variables (`EXAMPLE_STORE_ACCESS_KEY` and `EXAMPLE_STORE_SECRET_KEY` for
   the public bucket, `EXAMPLE_STATE_ACCESS_KEY` and `EXAMPLE_STATE_SECRET_KEY` for the private one, and
   `EXAMPLE_R2_ACCOUNT_ID`; the names are yours, `[publish]` holds only the names). The `push` job sets
   both pairs to the push token. The `refresh` job sets the first pair to the refresh-public token and the
   second to the refresh-private token.

   `refresh` writes only feeds; it reads the state file to refuse a store that was rolled back
   ([`docs/THREAT-MODEL.md`](THREAT-MODEL.md), "A stolen refresh token"). That guard holds only while the
   refresh job cannot write the private bucket. **Never give the refresh job one token with Object Read & Write on both buckets**: whoever holds it
   can lower the state file's record and get an older feed re-signed as the newest. The refresh-public
   token can still overwrite any object in the public bucket (and perhaps delete one; R2's documentation
   does not say whether its write permission excludes deletes). An overwritten object fails its signed
   hash, so that is a denial of updates, not a forgery.

   On AWS S3 (`store = "s3"`) make the same three as IAM policies: object read, write and delete
   (`s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`) where the table says Read & Write, `s3:GetObject`
   where it says Read only. Each also needs `s3:ListBucket` on its buckets (it can be limited to
   `<prefix>/*`): without it S3 answers 403, not 404, for a key that does not exist, and every run fails
   on its first missing key (`root-2.json`, a new channel's feed) with "answered status 403". lunepack
   never takes a 403 for "absent". Cloudflare R2 answers 404 and needs nothing extra.
4. **Add `[publish]`** to `lunepack.toml` (next section) and, if the app is packed per OS,
   `[install.<os>]`.
5. **Initialise the store**, once, from the directory where `keys set` ran, dry run first:

   ```sh
   lunepack publish init --release-dir release --dry-run
   lunepack publish init --release-dir release
   ```

   `init` uploads the roots, `keys.json` and the state file, and refuses if the store already holds other
   bytes at any of them. A rerun after a failure keeps what is already there with the same bytes and
   uploads the rest. An app that already has a prefix laid out the same way (`keys.json`, `feed-<channel>.json`,
   `<version>/` folders, and `lunepack-state.json` in the private bucket) needs no `init`.
6. **Protect the release path in the repository.** A secret that a workflow can read from any branch is not
   protected by an approval on one job, so none of these is a repository secret (an environment secret only
   reaches a job that names the environment, on a ref its rules allow). Make three environments, each
   limited under "Deployment branches and tags" to the refs it needs, and put the secrets in them:

   | Environment | Used by | Secrets | Rules |
   | --- | --- | --- | --- |
   | `release-pack` | `pack` | the release key | tags `v*` only |
   | `release-push` | `push` | the release key, the push token | tags `v*` only; required reviewers: the owner |
   | `release-refresh` | `refresh` | the release key, the refresh-public and refresh-private tokens | the default branch only |

   Also restrict who can create `v*` tags (a tag ruleset), protect the default branch, give the workflow
   one concurrency group (below), and keep a job's token to `contents: read`. A person or bot that can push a
   branch can then change the workflow but cannot get a key or a store token out of it.

## The `[publish]` table

```toml
[update]
feed = "https://updates.example.com/hello/"   # the public bucket's prefix, as a client reaches it
channel = "stable"

[install]
entry = "bin/hello"
name = "Hello"

[install.windows]                              # entry and icon only, per OS; the rest comes from [install]
entry = "bin/hello.exe"

[publish]
prefix = "hello"                               # one path segment: every object lives under <prefix>/
store = "r2"                                   # "r2", or "s3" with endpoint_env and region
account_id_env = "EXAMPLE_R2_ACCOUNT_ID"
access_key_env = "EXAMPLE_STORE_ACCESS_KEY"           # the public bucket's pair
secret_key_env = "EXAMPLE_STORE_SECRET_KEY"
private_access_key_env = "EXAMPLE_STATE_ACCESS_KEY"   # the private bucket's pair (both or neither;
private_secret_key_env = "EXAMPLE_STATE_SECRET_KEY"   # without them the pair above is used for both)
public_bucket = "example-updates"
private_bucket = "example-updates-private"
keep = 10                                      # releases kept per channel
deltas = 3                                     # earlier releases fetched as delta bases
feed_days = 90                                 # a feed's lifetime when it is signed
channels = ["stable", "beta"]
prerelease_channels = ["beta"]                 # a version with a pre-release part goes only here
require_targets = ["linux-x86_64", "windows-x86_64"]
```

(The `app_id` and the `[root]` that `lunepack init` wrote come before these tables.) `[publish]` holds the
*names* of environment variables and never a value. The keys, their defaults and limits are in
[`docs/CLI.md`](CLI.md), "`[publish]`". Three things to know:

- `require_targets` makes a publish fail when a target is missing, so a release with only some of the
  platforms never reaches the feed. Say what your users run.
- The public bucket's URL is `[update] feed`; `publish fetch` reads the feed there, with no credential.
- `pack --channel beta` writes `beta` as the channel of the packed app (it must be one of `channels`); a
  build that follows `beta` is packed that way.

## The job split

Keep the secrets apart. The release key signs manifests and feeds; the store credentials write buckets. No
job needs more than it uses.

| Job | Runs | Secrets | Does |
| --- | --- | --- | --- |
| `tools-<os>` | once per OS you pack on (not a matrix) | none | builds the CLI at a pinned version, uploads it, outputs its SHA-256 as `cli_sha256` |
| `build` | per target | none | builds the app |
| `pack` | per target | release key | checks the CLI, then `prebuilt fetch`, `publish fetch`, `pack`, `setup`, with `SOURCE_DATE_EPOCH` from the tag commit |
| `push` | once, after every `pack` | release key and the push token | checks the CLI, then `publish push --dry-run` and `publish push`; no `SOURCE_DATE_EPOCH` |
| `refresh` | scheduled | release key and the two refresh tokens | checks the CLI, then `publish refresh`; no `SOURCE_DATE_EPOCH` |

Why the CLI is built in its own job and checked by hash: no job that holds a key compiles anything.
Compiling `lunepack-cli` runs the build scripts of its dependencies, and in a key job they would run beside
the release key and the store tokens. So each `tools-<os>` job builds it with no secret and writes the
binary's SHA-256 to its job outputs. Every key job `needs:` its OS's tools job, downloads the binary and
refuses to run it unless its SHA-256 equals `needs.tools-<os>.outputs.cli_sha256`. The check is needed
because the `build` job runs your build, which includes third-party code (dependencies, build scripts,
package hooks), and a process it leaves running can use the run's artifact token to replace an artifact
the run uploaded earlier. It cannot write another job's outputs, so a replaced binary fails the check.
Besides the CLI only data artifacts pass: the build output, which `pack` packages and signs by design,
and the release directories, which `push` verifies completely, signatures and hashes, before it uploads
anything. The prebuilt runtime and stub are fetched inside `pack` and held to lunepack's pins by
`--require-pinned`.

Why `SOURCE_DATE_EPOCH` only in `pack`: it fixes the time documents are issued at, which makes a pack
byte-for-byte reproducible (so a rerun of `push` finds the same bytes in the store). In `push` and
`refresh` it would issue a feed at the tag's old time, so those commands refuse it. Set it per step in the
`pack` job, not for the whole workflow.

Why the concurrency group: two publishes at once could write the same feed. `push` and `refresh` re-read a
feed just before writing it and refuse if it moved, but the group is what keeps a refresh from starting
while a push runs. Give the publish and the refresh workflows the same group and `cancel-in-progress:
false`.

## A complete workflow

GitHub Actions; the names are generic, replace them. `lunepack-cli` installs the `lunepack` command; until
lunepack's first release is published, build it from a checkout in the `tools-<os>` jobs instead of
`cargo install`. Each job that holds a secret names its environment ("One-time setup", step 6), compiles
nothing, and checks the CLI it downloads before its first `lunepack` command.

```yaml
name: publish
on:
  push:
    tags: ["v*"]
  schedule:
    - cron: "17 4 * * 1"     # a weekly refresh
  workflow_dispatch: {}

concurrency:
  group: publish-example-app
  cancel-in-progress: false

permissions:
  contents: read

env:
  LUNEPACK_VERSION: "1.0.0"  # the lunepack-cli version you tested; pin it

defaults:
  run:
    shell: bash

jobs:
  # One job per OS that runs lunepack (not a matrix: each has its own output). No secret here.
  tools-linux:
    runs-on: ubuntu-latest
    outputs:
      cli_sha256: ${{ steps.hash.outputs.cli_sha256 }}
    steps:
      - run: cargo install lunepack-cli --locked --version "$LUNEPACK_VERSION" --root tools
      - id: hash
        run: echo "cli_sha256=$(sha256sum tools/bin/lunepack | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with: { name: tools-linux, path: tools/bin/lunepack }

  tools-windows:
    if: github.event_name == 'push'
    runs-on: windows-latest
    outputs:
      cli_sha256: ${{ steps.hash.outputs.cli_sha256 }}
    steps:
      - run: cargo install lunepack-cli --locked --version "$LUNEPACK_VERSION" --root tools
      - id: hash
        run: echo "cli_sha256=$(sha256sum tools/bin/lunepack.exe | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with: { name: tools-windows, path: tools/bin/lunepack.exe }

  build:
    if: github.event_name == 'push'
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest, target: linux-x86_64 }
          - { os: windows-latest, target: windows-x86_64 }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh --target "${{ matrix.target }}" --out build    # your build; no secret here
      - uses: actions/upload-artifact@v4
        with:
          name: build-${{ matrix.target }}
          path: build

  pack:
    needs: [build, tools-linux, tools-windows]
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest, target: linux-x86_64, tool: linux, exe: lunepack, kinds: "--kind runtime", extra: "" }
          - { os: windows-latest, target: windows-x86_64, tool: windows, exe: lunepack.exe, kinds: "--kind runtime --kind stub", extra: "--stub prebuilt/lunepack-stub-[0-9]*" }
    runs-on: ${{ matrix.os }}
    environment: release-pack      # the release key lives here, not in the repository
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with: { name: "tools-${{ matrix.tool }}", path: tools }
      - name: check the CLI against its tools job
        env:
          WANT: ${{ matrix.tool == 'linux' && needs.tools-linux.outputs.cli_sha256 || needs.tools-windows.outputs.cli_sha256 }}
        run: |
          GOT="$(sha256sum "tools/${{ matrix.exe }}" | cut -d' ' -f1)"
          if [ -z "$WANT" ] || [ "$GOT" != "$WANT" ]; then echo "the CLI is not the one tools-${{ matrix.tool }} built"; exit 1; fi
          chmod +x "tools/${{ matrix.exe }}"
      - run: tools/lunepack prebuilt fetch --target "${{ matrix.target }}" ${{ matrix.kinds }} --out prebuilt
      - uses: actions/download-artifact@v4
        with: { name: "build-${{ matrix.target }}", path: build }
      - name: fetch, pack and set up
        env:
          EXAMPLE_RELEASE_KEY: ${{ secrets.EXAMPLE_RELEASE_KEY }}
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
          tools/lunepack publish fetch --release-dir release --version "$VERSION"
          tools/lunepack pack --input build --version "$VERSION" --target "${{ matrix.target }}" \
              --release-dir release --sign env:EXAMPLE_RELEASE_KEY \
              --runtime prebuilt/lunepack-runtime-[0-9]* --require-pinned ${{ matrix.extra }}
          mkdir -p setup
          tools/lunepack setup release --version "$VERSION" --target "${{ matrix.target }}" \
              --out "setup/hello-${{ matrix.target }}-setup"
      - uses: actions/upload-artifact@v4
        with:
          name: release-${{ matrix.target }}
          path: release
      - uses: actions/upload-artifact@v4
        with:
          name: setup-${{ matrix.target }}
          path: setup

  push:
    needs: [pack, tools-linux]
    runs-on: ubuntu-latest
    environment: release-push      # the owner approves here; the release key and the push token live here
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with: { name: tools-linux, path: tools }
      - name: check the CLI against its tools job
        env:
          WANT: ${{ needs.tools-linux.outputs.cli_sha256 }}
        run: |
          GOT="$(sha256sum tools/lunepack | cut -d' ' -f1)"
          if [ -z "$WANT" ] || [ "$GOT" != "$WANT" ]; then echo "the CLI is not the one tools-linux built"; exit 1; fi
          chmod +x tools/lunepack
      - uses: actions/download-artifact@v4
        with: { name: release-linux-x86_64, path: release-linux-x86_64 }
      - uses: actions/download-artifact@v4
        with: { name: release-windows-x86_64, path: release-windows-x86_64 }
      - name: push
        env:
          EXAMPLE_RELEASE_KEY: ${{ secrets.EXAMPLE_RELEASE_KEY }}
          EXAMPLE_R2_ACCOUNT_ID: ${{ secrets.EXAMPLE_R2_ACCOUNT_ID }}
          EXAMPLE_STORE_ACCESS_KEY: ${{ secrets.EXAMPLE_PUSH_ACCESS_KEY }}   # the push token, for both buckets
          EXAMPLE_STORE_SECRET_KEY: ${{ secrets.EXAMPLE_PUSH_SECRET_KEY }}
          EXAMPLE_STATE_ACCESS_KEY: ${{ secrets.EXAMPLE_PUSH_ACCESS_KEY }}
          EXAMPLE_STATE_SECRET_KEY: ${{ secrets.EXAMPLE_PUSH_SECRET_KEY }}
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          tools/lunepack publish push --release-dir release-linux-x86_64 \
              --release-dir release-windows-x86_64 --version "$VERSION" \
              --sign env:EXAMPLE_RELEASE_KEY --dry-run
          tools/lunepack publish push --release-dir release-linux-x86_64 \
              --release-dir release-windows-x86_64 --version "$VERSION" \
              --sign env:EXAMPLE_RELEASE_KEY

  refresh:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    needs: [tools-linux]
    runs-on: ubuntu-latest
    environment: release-refresh   # default branch only; the release key and the two refresh tokens live here
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with: { name: tools-linux, path: tools }
      - name: check the CLI against its tools job
        env:
          WANT: ${{ needs.tools-linux.outputs.cli_sha256 }}
        run: |
          GOT="$(sha256sum tools/lunepack | cut -d' ' -f1)"
          if [ -z "$WANT" ] || [ "$GOT" != "$WANT" ]; then echo "the CLI is not the one tools-linux built"; exit 1; fi
          chmod +x tools/lunepack
      - name: refresh the feeds
        env:
          EXAMPLE_RELEASE_KEY: ${{ secrets.EXAMPLE_RELEASE_KEY }}
          EXAMPLE_R2_ACCOUNT_ID: ${{ secrets.EXAMPLE_R2_ACCOUNT_ID }}
          EXAMPLE_STORE_ACCESS_KEY: ${{ secrets.EXAMPLE_REFRESH_PUBLIC_ACCESS_KEY }}   # public: read and write
          EXAMPLE_STORE_SECRET_KEY: ${{ secrets.EXAMPLE_REFRESH_PUBLIC_SECRET_KEY }}
          EXAMPLE_STATE_ACCESS_KEY: ${{ secrets.EXAMPLE_REFRESH_PRIVATE_ACCESS_KEY }}  # private: read only
          EXAMPLE_STATE_SECRET_KEY: ${{ secrets.EXAMPLE_REFRESH_PRIVATE_SECRET_KEY }}
        run: |
          tools/lunepack publish refresh --sign env:EXAMPLE_RELEASE_KEY \
              --if-expiring-within-days 30 --skip-if-unpublished
```

Notes on the example:

- Use the targets your app ships and list them in `require_targets`. A Windows target needs `--stub`; a
  macOS target adds `--ui`, an assemble-and-sign step and a macOS runner, and a Linux or Windows window needs
  `--ui` too ([`docs/CLI.md`](CLI.md), "Windows targets" and "macOS targets"). `--require-pinned` refuses a
  runtime that is not one lunepack pins. The setup files the `pack` job builds are for your download page;
  they are not part of the publish.
- Code signing of the app (`[codesign.<os>]`) and notarization run inside `pack`; their secrets belong to the
  `pack` job only.
- A feed lives `feed_days` (90 by default); the weekly `refresh` with `--if-expiring-within-days 30`
  re-signs a feed in its last 30 days, so a quiet app's clients never see an expired feed.
- A scheduled job runs on the default branch; keep `lunepack.toml` there.
- No job reads a repository secret. The release key and the three tokens are secrets of the three
  environments, so a workflow that runs on a branch (or `workflow_dispatch` there) gets none of them, and
  only `push` waits for the owner. `refresh` holds the two refresh tokens: it can write the public bucket
  and only read the private one.
- The `tools-<os>` jobs hold no secret and name no environment. Add `tools-macos` (on a macOS runner, the
  same steps) when you pack a macOS target, and make each key job that runs on that OS check against it.
  A key job never runs `cargo`, `make` or any other build: it only runs the checked CLI.
- Pin `LUNEPACK_VERSION` and update it on purpose: the one build of the tools jobs runs `pack`, `push` and
  `refresh`.

## Rerun and recovery

A `push` that stops part-way (a network error, a timeout, a cancelled job) leaves the store consistent for
clients: it uploads packs and deltas, then manifests, and only then rewrites a feed, so a feed never lists
something that is missing. To finish it, **run the `push` job again with the same release directories** (in
CI: "re-run failed jobs"; the `pack` artifacts do not change). Objects already uploaded are kept when
byte-equal, a feed that already lists the version is not added to again, and the rest completes.

- Do not run `fetch` and `pack` again for a version a feed already lists: `fetch` refuses it ("is already
  published"), because a second pack would build different deltas.
- If a rerun says "the store already holds other bytes", the packs differ from the ones uploaded (the build
  is not reproducible, or the version was published from another commit). Do not overwrite or delete. Fix
  the cause or publish the next version.
- If the first push of a version never got as far as a feed (an abandoned push), `lunepack publish plan`
  lists it under "abandoned" with the keys of its manifests, for the owner to rerun or clean up by hand.
- A purge that fails (a store error while deleting) is not an error of the publish: the key stays in the
  pending-deletes record and the next `push` retries it, after re-checking that no feed lists its version.
  A `refresh` never deletes and never writes the private bucket, so it leaves the record alone; `publish
  plan` lists what is pending.
- A `push` that stopped after writing a feed but before its state file (the last write) leaves the
  state file's record one step behind, and the scheduled `refresh` guards against a rolled-back feed by
  that record. Rerun that `push` before the next `refresh` runs.
- The owner's `publish init` and `publish keys` are rerun the same way, with the same directory: a
  document already in the store with the same bytes is kept, and the rest is uploaded. When a key-set
  upload fails, `publish keys` removes the roots it had uploaded (it prints `removed:`, or `not removed:`
  when that fails too). Until the rerun, a store left with a new root but the old `keys.json` makes
  `push`, `refresh` and `plan` stop with "the store's key set does not verify"; the rerun of `publish
  keys` finishes it. Do not upload or delete a root or `keys.json` by hand.

## Retention

`keep` releases stay in each channel's feed, the newest by version precedence (so `1.10.0` is newer than
`1.9.0`). The version being published is always kept. When a release drops out of every feed, its
manifests, packs and deltas are deleted by the next `push`, after the feeds that stop listing it are
written and only if no feed lists the version any more.

"Any feed" means the feeds of the `[publish]` channels and also the feed of every channel the state file
records, which the commands read from the public bucket even when `[publish] channels` no longer names the
channel; `plan` shows such a feed as "not in [publish] channels". They are never written or re-signed, and
what they list is never purged, for as long as the feed object stays in the bucket. A feed of a channel
the state file has no record of (one an old script published and `publish` never did) is not known to the
commands, so keep such a channel in `channels` until its feed has expired. To retire a channel, take it out
of `channels` and delete its feed object yourself (the owner's hand work, never an agent's); the objects
that only that feed listed are then named by nothing, so, like other unnamed objects, they are not purged
automatically and the owner removes them by hand. A guard feed that does not verify (signed by a key that
was removed) stops every command, naming it: delete that feed object, or restore the keys.

Objects that no manifest names (a file placed by hand, the leftovers of an abandoned upload) are not
purged automatically; the owner removes them by hand.

## Changing the key set or revoking a key (owner only)

`push` and `refresh` never write `keys.json` or a root; a key-set change reaches the store only through
`lunepack publish keys`. It is the owner's command, like `init`: never an agent's, and never run in CI (the
root key signs the change, and the root key is offline). An agent that is asked to revoke a key stops and
says so.

Revoking a leaked release key takes two moves of the key set (`docs/CLI.md`, "Revoking a release key"),
with `publish keys` as the way each move reaches the store, and three steps between them. The old key stays
trusted by clients until the second move is published, so do all five without delay.

1. **Move 1: add the new key.** On the owner's machine, fetch the published state and list the new
   release key beside the old one:

   ```sh
   lunepack publish fetch --release-dir revoke --version 999999.0.0
   lunepack keys set --release-dir revoke --release-key <old public key> --release-key <new public key> \
       --threshold 1 --sign <root signer> --trust-release-dir
   lunepack publish keys --release-dir revoke --dry-run
   lunepack publish keys --release-dir revoke
   ```

   (`--trust-release-dir` is needed because the owner's local state file does not record what was fetched;
   `publish keys` compares the new key set with the private state file, which does.)
2. **Replace the release key in CI.** Put the new key in `EXAMPLE_RELEASE_KEY` of all three environments,
   `release-pack`, `release-push` and `release-refresh`. Every job then signs with the new key. A scheduled
   `refresh` that still held the old key would re-sign the feeds with it, and move 2 would be refused
   again; after move 2 it would fail on every run.
3. **Publish a new version** the usual way ("Ship a new version"). Its manifests and the feeds it writes
   are signed with the new key. Do this before step 4, so that no feed is left without a release.
4. **Drop the releases only the old key signed** (when the old key was the only one, that is every
   earlier release), re-signing every feed with the new key, with the refresh tokens (or the push
   token) set in the shell:

   ```sh
   lunepack publish refresh --sign <new signer> --drop 1.3.0 --drop 1.4.0 --dry-run
   lunepack publish refresh --sign <new signer> --drop 1.3.0 --drop 1.4.0
   ```

   `--drop` takes each named release out of every `[publish]` channel's feed that lists it. It refuses a
   version that a feed of a channel no longer in `channels` lists (such a feed is never written): put the
   channel back into `channels` for this step. The dropped releases' manifests, packs and deltas stay in
   the public bucket, listed by no feed. No client fetches them, and no `push` purges them; the owner may
   delete them by hand later. A client still on a dropped version updates to the new one as usual (the
   new version's deltas are its own files).
5. **Move 2: remove the old key.** Fetch again, list only the new key, and upload it:

   ```sh
   lunepack publish fetch --release-dir revoke-2 --version 999999.0.0
   lunepack keys set --release-dir revoke-2 --release-key <new public key> \
       --threshold 1 --sign <root signer> --trust-release-dir
   lunepack publish keys --release-dir revoke-2 --dry-run
   lunepack publish keys --release-dir revoke-2
   ```

   `publish keys` refuses, naming each feed and manifest, while anything in the store still needs the old
   key, and writes nothing. Then drop what it names (step 4) and run `publish keys --release-dir revoke-2`
   again: keep that directory, because `keys set` recorded its key set in the owner's local state file and
   a second `keys set` on a new fetch is refused.

Through `publish`, the first key set (both keys) is uploaded before the second, unlike the hand flow in
`docs/CLI.md` where nothing is uploaded between the moves.

A root rotation (`lunepack keys rotate-root`) is published the same way: `publish keys` uploads the new
`root-<k>.json` first, then `keys.json`, then updates the state file's record of the root and key set. It
refuses a directory whose roots do not continue the store's, a `keys.json` that is not newer than the
store's, and anything that would lower the state file's record. A failed run is repeated as it is, with
the same directory: the parts already in the store are kept and the rest is uploaded. If the upload of a
root or of `keys.json` fails, the run first removes the roots it uploaded, so clients keep reading the old
key set ("Rerun and recovery"). Run it with `--dry-run` first.

## When something is refused

| The message says | It means | What to do |
| --- | --- | --- |
| `run \`lunepack publish init\` first` | the store has no state file or no `keys.json` | the owner runs `publish init` ("One-time setup") |
| `the environment variable X ... is not set` | a store credential is missing from the job | add the secret and pass it in the job's `env` |
| `SOURCE_DATE_EPOCH is set` | `push`, `refresh`, `init` or `keys` ran with it | unset it; set it only in the `pack` step |
| `version X is already published` | `fetch` found the version in a feed | the version is out; publish the next one |
| `the store changed since fetch` | another publish or refresh wrote between `fetch` and `push` | run the pipeline again from `fetch` |
| `... changed in the store since this run read it` | the race check: a feed moved during the run (a refresh and a push at once, or two pushes) | on `push`, the message says to run `fetch` and `pack` again, then `push` (the other writer's feed is what `fetch` must see); on `refresh`, run `refresh` again; check for a concurrent run |
| `the store's key set does not verify` | a `publish keys` stopped after uploading a root and before `keys.json`, so the store's last root did not sign its `keys.json` | the owner runs that `publish keys` again with the same directory; never upload or delete a root by hand |
| `documents older than the state file records` | `refresh` found a feed, key set or root in the store older than the private state file records: a rolled-back bucket | it signed and wrote nothing; the owner restores the newer documents from the state file's history or investigates the bucket; never re-sign over it |
| `answered status 403` on a `GET` | the token cannot read the bucket, or (AWS S3) lacks `s3:ListBucket` | give the token the missing access ("One-time setup", step 3); a 403 is never treated as "absent" |
| `the store already holds other bytes at` | an object of this version differs from the upload | see "Rerun and recovery"; never delete by hand to get past it |
| `the release has no X target` | a `require_targets` target is missing | fix the failed `pack` job and re-run |
| `... is in ... but no manifest of the release names it` | a stray file in `<version>/` | remove it from the release directory |
| `the release would not verify` | a retained release or the new one fails `verify` | read the line before it; do not publish around it |

## Rules for agents

An agent that works on an app's repository can prepare and check a publish. It never runs one against a
real store.

**An agent may run** (with throwaway keys and a local directory standing in for the store):

- `lunepack publish fetch` (it reads no credential), `lunepack pack`, `lunepack setup`, `lunepack verify`,
  `lunepack inspect`;
- `lunepack publish plan --store-dir <dir>` and `lunepack publish push --dry-run --store-dir <dir>`, against
  a local test store (`<dir>/public` and `<dir>/private`) set up with throwaway keys made by
  `lunepack keys gen`, never the real ones;
- edits to the workflow, `lunepack.toml`'s `[publish]` and `[install.<os>]` tables, and the build, as the
  task asks.

**An agent never**:

- runs `publish push`, `publish refresh` (with or without `--drop`), `publish init` or `publish keys`
  against a real store, with or without `--dry-run`, and never starts the publish workflow or approves
  its environment;
- puts a release key, a root key or a store token in a repository secret, or in an environment whose rules
  allow a branch, or adds a job that holds one without an environment;
- compiles anything in a job that holds a key or a store token, or runs a `lunepack` program there without
  first checking its SHA-256 against the output of the `tools-<os>` job that built it;
- reads, prints, copies, logs or stores a release key, a root key or a store credential, in a file, a
  command line, a commit or an output; a text tool is not to be run on a key or credential file;
- edits the trust root (the `[root]` table, `keys.json`, a `root-<k>.json`) or generates keys that are
  meant to be real;
- sets `SOURCE_DATE_EPOCH` for a whole workflow, or for `push`, `refresh` or `init`;
- deletes, overwrites or hand-uploads an object in the store, or "fixes" a refusal by bypassing it;
- reuses a published version or moves a published tag.

When a step needs one of these, stop and say what is needed and why; the owner does it.
