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
3. **What runs**, in order: `tools` (the `lunepack` CLI and the prebuilt runtime for each target) →
   `build` (your app, per target) → `pack` (per target: `publish fetch`, `pack`, `setup`; the release key
   only) → `push` (`publish push --dry-run`, then `publish push`; the release key and the store
   credentials, behind the owner's approval). A scheduled `refresh` workflow keeps the feeds from
   expiring.
4. **Check the result** without any credential. Fetch the public state into an empty directory and look at
   the version folders it brings (the newest earlier releases, as delta bases):

   ```sh
   lunepack publish fetch --release-dir /tmp/published-check --version 999999.0.0
   ls /tmp/published-check
   ```

   The command verifies `keys.json` and every feed it finds under the app's root, so exit 0 means the
   feeds are intact. The owner can see everything, including what a push would add and drop, with
   `lunepack publish plan --version <version>` (it needs the store credentials, so an agent does not run it
   against a real store).
5. **If a job fails**, read its first error line and find it in "When something is refused" below. Re-run
   only the failed job; do not delete anything in the store by hand and do not bump the version. A failed
   `push` job is re-run as it is: its inputs are the artifacts of the `pack` jobs, which do not change.

## One-time setup

This is the owner's work, done once per app, on the owner's machine. An agent does not do it and does not
touch the keys it makes ("Rules for agents").

1. **Make the keys** and write `lunepack.toml`: `lunepack init`, `lunepack keys gen`, `lunepack keys set`
   ([`docs/KEY-CEREMONY.md`](KEY-CEREMONY.md)). The root key stays offline. The release key goes into the
   CI secret `EXAMPLE_RELEASE_KEY` (a PKCS#8 PEM; `--sign env:EXAMPLE_RELEASE_KEY` reads it). Commit
   `lunepack.toml` (it holds public keys and names, never a secret).
2. **Make two buckets** in the store: a public one that a CDN or the store's public URL serves at
   `[update] feed`, and a private one (not served). The public bucket holds everything a client reads; the
   private one holds the publisher's state file and the pending-deletes record.
3. **Make a store API token** limited to those two buckets, with object read and write (no bucket
   administration), and put its three values in CI secrets: `EXAMPLE_R2_ACCOUNT_ID`,
   `EXAMPLE_STORE_ACCESS_KEY`, `EXAMPLE_STORE_SECRET_KEY` (the names are yours; `[publish]` holds only the
   names).
4. **Add `[publish]`** to `lunepack.toml` (next section) and, if the app is packed per OS,
   `[install.<os>]`.
5. **Initialise the store**, once, from the directory where `keys set` ran, dry run first:

   ```sh
   lunepack publish init --release-dir release --dry-run
   lunepack publish init --release-dir release
   ```

   `init` uploads the roots, `keys.json` and the state file, and refuses if any of them is already in the
   store. An app that already has a prefix laid out the same way (`keys.json`, `feed-<channel>.json`,
   `<version>/` folders, and `lunepack-state.json` in the private bucket) needs no `init`.
6. **Protect the release path in the repository**: restrict who can push `v*` tags, put the `push` job in
   an environment that needs the owner's approval, and give the workflow one concurrency group (below).

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
access_key_env = "EXAMPLE_STORE_ACCESS_KEY"
secret_key_env = "EXAMPLE_STORE_SECRET_KEY"
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
| `tools` | per OS | none | installs the `lunepack` CLI; `lunepack prebuilt fetch` for the target's runtime, UI and stub |
| `build` | per target | none | builds the app |
| `pack` | per target | release key | `publish fetch`, `pack`, `setup`, with `SOURCE_DATE_EPOCH` from the tag commit |
| `push` | once, after every `pack` | release key and store credentials | `publish push --dry-run`, then `publish push`; no `SOURCE_DATE_EPOCH` |
| `refresh` | scheduled | release key and store credentials | `publish refresh`; no `SOURCE_DATE_EPOCH` |

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
lunepack's first release is published, build it from a checkout instead of `cargo install`.

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

defaults:
  run:
    shell: bash

jobs:
  tools:
    if: github.event_name == 'push'
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest, target: linux-x86_64, kinds: "--kind runtime" }
          - { os: windows-latest, target: windows-x86_64, kinds: "--kind runtime --kind stub" }
    runs-on: ${{ matrix.os }}
    steps:
      - run: cargo install lunepack-cli --locked --root tools
      - run: tools/bin/lunepack prebuilt fetch --target "${{ matrix.target }}" ${{ matrix.kinds }} --out prebuilt
      - uses: actions/upload-artifact@v4
        with:
          name: tools-${{ matrix.target }}
          path: |
            tools/bin
            prebuilt

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
      - run: ./build.sh --target "${{ matrix.target }}" --out build    # your build
      - uses: actions/upload-artifact@v4
        with:
          name: build-${{ matrix.target }}
          path: build

  pack:
    needs: [tools, build]
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest, target: linux-x86_64, extra: "" }
          - { os: windows-latest, target: windows-x86_64, extra: "--stub prebuilt/lunepack-stub-[0-9]*" }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with: { name: "tools-${{ matrix.target }}", path: "." }
      - uses: actions/download-artifact@v4
        with: { name: "build-${{ matrix.target }}", path: build }
      - name: fetch, pack and set up
        env:
          EXAMPLE_RELEASE_KEY: ${{ secrets.EXAMPLE_RELEASE_KEY }}
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
          chmod +x tools/bin/* prebuilt/*
          tools/bin/lunepack publish fetch --release-dir release --version "$VERSION"
          tools/bin/lunepack pack --input build --version "$VERSION" --target "${{ matrix.target }}" \
              --release-dir release --sign env:EXAMPLE_RELEASE_KEY \
              --runtime prebuilt/lunepack-runtime-[0-9]* --require-pinned ${{ matrix.extra }}
          mkdir -p setup
          tools/bin/lunepack setup release --version "$VERSION" --target "${{ matrix.target }}" \
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
    needs: [pack]
    runs-on: ubuntu-latest
    environment: publish          # the owner approves here
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with: { name: tools-linux-x86_64, path: "." }
      - uses: actions/download-artifact@v4
        with: { name: release-linux-x86_64, path: release-linux-x86_64 }
      - uses: actions/download-artifact@v4
        with: { name: release-windows-x86_64, path: release-windows-x86_64 }
      - name: push
        env:
          EXAMPLE_RELEASE_KEY: ${{ secrets.EXAMPLE_RELEASE_KEY }}
          EXAMPLE_R2_ACCOUNT_ID: ${{ secrets.EXAMPLE_R2_ACCOUNT_ID }}
          EXAMPLE_STORE_ACCESS_KEY: ${{ secrets.EXAMPLE_STORE_ACCESS_KEY }}
          EXAMPLE_STORE_SECRET_KEY: ${{ secrets.EXAMPLE_STORE_SECRET_KEY }}
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          chmod +x tools/bin/lunepack
          tools/bin/lunepack publish push --release-dir release-linux-x86_64 \
              --release-dir release-windows-x86_64 --version "$VERSION" \
              --sign env:EXAMPLE_RELEASE_KEY --dry-run
          tools/bin/lunepack publish push --release-dir release-linux-x86_64 \
              --release-dir release-windows-x86_64 --version "$VERSION" \
              --sign env:EXAMPLE_RELEASE_KEY

  refresh:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install lunepack-cli --locked --root tools
      - name: refresh the feeds
        env:
          EXAMPLE_RELEASE_KEY: ${{ secrets.EXAMPLE_RELEASE_KEY }}
          EXAMPLE_R2_ACCOUNT_ID: ${{ secrets.EXAMPLE_R2_ACCOUNT_ID }}
          EXAMPLE_STORE_ACCESS_KEY: ${{ secrets.EXAMPLE_STORE_ACCESS_KEY }}
          EXAMPLE_STORE_SECRET_KEY: ${{ secrets.EXAMPLE_STORE_SECRET_KEY }}
        run: |
          tools/bin/lunepack publish refresh --sign env:EXAMPLE_RELEASE_KEY \
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
  pending-deletes record and the next `push` or `refresh` retries it, after re-checking that no feed lists
  its version.

## Retention

`keep` releases stay in each channel's feed, the newest by version precedence (so `1.10.0` is newer than
`1.9.0`). The version being published is always kept. When a release drops out of every feed, its
manifests, packs and deltas are deleted, after the feeds that stop listing it are written and only if no
feed lists the version any more. Objects that no manifest names (a file placed by hand, the leftovers of
an abandoned upload) are not purged automatically; the owner removes them by hand.

## When something is refused

| The message says | It means | What to do |
| --- | --- | --- |
| `run \`lunepack publish init\` first` | the store has no state file or no `keys.json` | the owner runs `publish init` ("One-time setup") |
| `the environment variable X ... is not set` | a store credential is missing from the job | add the secret and pass it in the job's `env` |
| `SOURCE_DATE_EPOCH is set` | `push`, `refresh` or `init` ran with it | unset it; set it only in the `pack` step |
| `version X is already published` | `fetch` found the version in a feed | the version is out; publish the next one |
| `the store changed since fetch` | another publish or refresh wrote between `fetch` and `push` | run the pipeline again from `fetch` |
| `... changed in the store since this run read it` | the race check: a feed moved during the push | re-run the `push` job; check for a concurrent run |
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

- runs `publish push`, `publish refresh` or `publish init` against a real store, with or without
  `--dry-run`, and never starts the publish workflow or approves its environment;
- reads, prints, copies, logs or stores a release key, a root key or a store credential, in a file, a
  command line, a commit or an output; a text tool is not to be run on a key or credential file;
- edits the trust root (the `[root]` table, `keys.json`, a `root-<k>.json`) or generates keys that are
  meant to be real;
- sets `SOURCE_DATE_EPOCH` for a whole workflow, or for `push`, `refresh` or `init`;
- deletes, overwrites or hand-uploads an object in the store, or "fixes" a refusal by bypassing it;
- reuses a published version or moves a published tag.

When a step needs one of these, stop and say what is needed and why; the owner does it.
