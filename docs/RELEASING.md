# Releasing lunepack

The runbook of a lunepack release: the one-time key ceremony, the rehearsal, the release itself, and
what to do when something fails, when the project key is replaced, and when it leaks. It is written for
the maintainer. Every step is marked **[user]** (done by the maintainer, by hand, in GitHub's settings
or at a keyboard) or **[automatic]** (done by the release workflow, `.github/workflows/release.yml`), and
a step that cannot be taken back is marked **(cannot be undone)**.

No part of the ceremony, no approval, no secret and no publication is done by a coding agent or inside a
CI job that nobody approved: an agent does not generate, read, print, copy or store the project key or the
file that holds it, does not set, list or delete a secret, does not create or edit the environment,
does not approve a run, and does not push a tag or publish a crate. The documents that explain what the
key is worth are [`docs/THREAT-MODEL.md`](THREAT-MODEL.md), section "lunepack's own supply chain", and
[`SECURITY.md`](../SECURITY.md).

## How the blocks below were made

The commands that need no GitHub were run, in a scratch directory, with throwaway keys made at that
moment and kept under the file extension `.lpk`, with relative paths; the output under them is what they
printed. Public keys, key ids and digests are shortened to `8 characters...4 characters`, as in the other
guides; the real ones are 64 characters. A block marked "(not run: the user's)" needs GitHub or a real key
and was not run; no real key was made, and the key constants in the source are still empty.

## What a release is

| Mode | Started by | What happens |
| --- | --- | --- |
| `dry-run` | a push to `main` or `orch/**` that touches the release files, or a dispatch | **[automatic]** builds and assembles, and signs the list with a throwaway key made in the job; nothing is published or signed with the project key |
| `binaries` | **[user]**, a dispatch on `main` | phase 1: build, assemble, the draft `v<version>`, the signing job (it waits for the approval), the envelope attached to the draft |
| `rehearsal` | **[user]**, a dispatch on `main` | `binaries` into a draft `v<version>-rehearsal`; the list says `rehearsal: true` |
| `tag` | **[user]**, the push of the tag `v<version>` on the pin commit | phase 2: prove the pins, add the CLI files, publish the draft |
| `rehearsal-finalize` | **[user]**, a dispatch on the branch `release-rehearsal` | `tag` against the rehearsal draft; publishes nothing |

The release has two proofs, and each shows one thing. The **pins** bind exact bytes to a CLI: the CLI of a
version carries the list of the prebuilt binaries of that version, and `pack` and `prebuilt fetch` accept
only those bytes. The **signature** binds that list to a run of the release workflow on `main` that the
maintainer approved: the project key was held by one job, `sign`, and that job signed this list. The
signature says nothing about how the files were built, and nothing is attested. The `lunepack` CLI file on
the release page carries no proof: it is built at the tag, after the one signing. The threat model says
what that leaves.

The order of a release: the ceremony (once) → the rehearsal (before the first release) → phase 1 on `main`
at a commit A → the pin commit B on `main` → the tag on B → phase 2 → `lunepack prebuilt fetch` against
the public release → `cargo publish`.

## 1. The key ceremony and the signing environment **[user]**, once, before the rehearsal

Nothing in this section is run by an agent or by CI. Until it is done, `PROJECT_ROOTS` in
`crates/lunepack-cli/src/project_key.rs` is empty, the CLI is in the state `no-key`, nothing is pinned, and
the workflow refuses every mode but `dry-run` (its `preflight` job stops on `no-key`).

### 1.1 Make the key

On a machine you trust, onto an encrypted or removable volume, outside every checkout of the repository.
lunepack's key files are not encrypted: the file is a PKCS#8 PEM with mode 0600
([`CLI.md`, "Key file format"](CLI.md)), so what protects it is the volume it is on. The directory must
exist. Only the two lines `public:` and `id:` ever leave the machine.

```
$ mkdir keyvol
lunepack keys gen keyvol/project.lpk
public: dade2c93...af1b
id: d589939d...04fc
wrote the private key to keyvol/project.lpk
```

In the session `keyvol` is a scratch directory standing in for the volume, and the key is a throwaway.
Make yours at the path of the volume (`lunepack keys gen /path/to/volume/lunepack-project.lpk`). The
command never overwrites a file. A key of a real release is made once; the same command makes the
replacement of section 7.

### 1.2 Create the environment

(not run: the user's.) In the repository's settings on GitHub, under Environments, create `release-signing`
with exactly these settings:

- **Required reviewers:** the maintainer. This is the approval of section 3.
- **Prevent self-review:** off. The maintainer starts a run and approves it.
- **Allow administrators to bypass configured protection rules:** off.
- **Deployment branches and tags:** "Selected branches and tags", with the one branch rule `main` and no
  other rule.

GitHub creates a missing environment, with no rule at all, the first time a job names it. That is why the
workflow checks these settings before it asks for the key (step 1.6), and why nothing here can be left to
memory.

### 1.3 Put the key in the environment, and nowhere else

(not run: the user's.) The key goes in as a secret of the environment `release-signing`, read from standard
input, so that it is never on a command line:

```
gh secret set LUNEPACK_PROJECT_KEY --env release-signing --repo lune-rs/lunepack < <the key file>
```

Then check that the secret is an environment secret and not a repository or an organization secret:

```
gh secret list --env release-signing --repo lune-rs/lunepack
gh secret list --repo lune-rs/lunepack
gh secret list --org lune-rs
```

The first lists `LUNEPACK_PROJECT_KEY`; the second and the third do not. A secret can be replaced but never
read back, not even by you.

### 1.4 The key file afterwards

Signing happens only in the workflow, so the file is not needed again. The recommendation is to keep no
copy: remove the file with its volume. A copy kept outside GitHub is a second place that can leak, and
it is the one place where the key is not protected by the environment's rules. If you keep one, keep it on an
offline, encrypted medium. Losing it costs nothing but a rotation (section 7.2).

### 1.5 The public key into the source

The public key is public. Add one entry to `PROJECT_ROOTS` in `crates/lunepack-cli/src/project_key.rs`:

```rust
pub const PROJECT_ROOTS: &[ProjectKeySet<'static>] = &[ProjectKeySet {
    version: 1,
    threshold: 1,
    keys: &["<the 64 characters printed as public:>"],
}];
```

and the row of the same key in the table of [`SECURITY.md`](../SECURITY.md), section "The project's key
sets", replacing the sentence that no key has been published:

```
| Version | Threshold | Public key | Key id | State |
| --- | --- | --- | --- | --- |
| 1 | 1 | `<public key>` | `<key id>` | current |
```

(the two 64-character values, in a table row: a bullet list beside the word "key" is flagged by the secret
scan). The checks are `cargo test -p lunepack-cli --locked` (the constants are well formed: versions 1, 2,
... without a gap, no key twice, every set valid) and `bash scripts/tests/run.sh`, whose
`test-project-key-docs.sh` fails unless SECURITY.md holds exactly the rows the built CLI reports. The
commit lands on `main`. You may hand the two public lines to the person who prepares that commit; the key
file is never needed for it.

### 1.6 Check the environment

(not run: the user's.) With your own `gh` login, which reads settings the workflow's token may not:

```
GITHUB_REPOSITORY=lune-rs/lunepack scripts/release/check-signing-env.sh binaries
```

It passes only with a required reviewer, administrator bypass off and the single branch policy `main`, and
prints `release-signing: ok (a required reviewer, no administrator bypass, the branch main only)`. It
reads settings only: it changes nothing and reads no secret. The workflow runs it again in its
`preflight` job, in every mode (in `dry-run` it only prints its verdict). It guards against a setting left off; it does not stop
someone who administers the repository from changing the settings afterwards.

### 1.7 The other settings

(not run: the user's.) Switch on private vulnerability reporting (Settings, Code security) so that
[`SECURITY.md`](../SECURITY.md) is true. Protect the tags `v*` with a tag ruleset that lets only the
maintainer create them and blocks updates and deletions. The release jobs that create, complete and publish
a release do not wait for anyone; the tag rule is what decides who can publish.

### 1.8 The rehearsal

Section 4.

## 2. Before any release **[user]**

- Look at the last run of `weekly.yml`: the fuzz campaign and `cargo deny` (advisories and licences). A new
  advisory is a reason to look before releasing, not a rule that turns unrelated pushes red.
- On `main`: `./scripts/gate.sh`, `./scripts/e2e.sh`, `./scripts/e2e-linux-machine.sh` and, on a disposable
  Mac, `scripts/e2e-macos-machine.sh` (the macOS per-machine suite has never run in CI).
- `scripts/publish-dry-run.sh` packages the ten crates of the publish set and builds each package alone;
  it needs a clean work tree and the network for the crates.io index, it prints about 75 harmless
  "ignoring test ... not included in the published package" warnings, and it uploads nothing. The packaged
  crates carry their licence as an SPDX expression; the licence files are at the repository root and are
  not inside the packages.
- Raise the version if this release has a new one. A version bump is one commit that changes:
  `Cargo.toml` (`version` of `[workspace.package]` and the `=x.y.z` requirements between the crates),
  `Cargo.lock` and `fuzz/Cargo.lock`, `CHANGELOG.md`, and the fuzz seeds of the UI harness, which embed the
  workspace version in their build id and so fail `committed_seeds_match_the_writer` until they are written
  again:

  ```
  LUNEPACK_WRITE_SEEDS=1 cargo test -p lunepack-testkit --test fuzz_replay committed_seeds
  ```

  The commit that raises the version after a release also truncates `crates/lunepack-cli/prebuilt.json`
  and `crates/lunepack-cli/prebuilt.sig.json` to zero length: a list of the old version beside the new
  version is the state `other-version`, and the unit test over the committed constants fails on `main`
  otherwise.
- The generated notices file, `crates/lunepack-cli/THIRD-PARTY-NOTICES.txt`, may carry a licence text that one
  rule of the maintainer's private denylist matches. The exception lives in that private file, not here: the
  maintainer appends `::skip-file:: <repo-relative path>` to the rule's line (for example
  `some-term ::skip-file:: crates/lunepack-cli/THIRD-PARTY-NOTICES.txt`; several markers, several paths). The
  scan then skips that rule's hits on content lines of exactly that tracked path, and nothing else (not the path,
  not commit messages, not other files). A malformed marker, or a near miss of one anywhere on the line (such as
  `::skip-file:` or `:: Skip-File ::`), is an error naming the line number; a marker naming a path that is not
  tracked prints a warning naming the rule number. The summary line counts the parsed paths
  (`denylist: N rules, M skip-files, K hits`), so a marker that parsed shows there. Never write a denylist term anywhere in
  the repository.
- `main` is frozen from the commit A that phase 1 builds until the tag: the tag run fails when A..B changes
  any file but the two of the pin commit, so a changelog date added late is enough to fail it.

## 3. Approving a signing run **[user]**, once per release and once per rehearsal

The approval is the only human gate, and the click does one thing: it hands the key to the one job `sign`.
Before you click, check, in this order:

1. The run was started by you, on `main`, at the commit you mean to release, in the mode you mean.
2. CI has completed green on that same commit: `gh run list --commit <sha> --workflow ci.yml` (not run:
   the user's). A red, missing or unfinished run is a reason to reject.
3. The run's `preflight` job is green. It ran the workflow lint and the release-script tests at that commit,
   which hold the key's path down to one step.
4. No other run is waiting.
5. You have read what decides what the signing job runs and what the CLI signs:

   ```
   git diff <base>..<commit> -- .github/workflows scripts/release crates/lunepack-cli crates/lunepack-crypto crates/lunepack-core
   ```

   (not run: it needs a release.) `<base>` is the `source_commit` of the last released list: put it in a
   file with `git show v<previous>:crates/lunepack-cli/prebuilt.json > previous-list.json` and read it
   with `lunepack prebuilt check --list previous-list.json --json`, which prints, for a list:

   ```
   $ lunepack prebuilt check --list prebuilt-0.1.0.json --json
   {"binaries":[{"asset":"lunepack-runtime-0.1.0-linux-x86_64","kind":"runtime","sha256":"53b79f7a...f32a","size":14,"target":"linux-x86_64"},{"asset":"lunepack-ui-0.1.0-windows-x86_64.exe","kind":"ui","sha256":"5ad1e384...74a8","size":10,"target":"windows-x86_64"}],"rehearsal":false,"source_commit":"0123456789abcdef0123456789abcdef01234567","version":"0.1.0"}
   ```

   Before the first release `<base>` is the commit that added the first key set to `project_key.rs`. At the
   first approval, the rehearsal, also read the job `sign` of `release.yml`, `scripts/release/sign-list.sh`
   and `crates/lunepack-cli/src/cmd_prebuilt.rs` whole.

A refusal by any script is never worked around by signing somewhere else.

## 4. The rehearsal **[user]**, before the first release

The rehearsal runs the whole privileged path against a draft that is never published. Its list is signed by
the real key and says `rehearsal: true` inside the signed bytes; every consumer refuses such a list as a
release, which is the only reason it is harmless. It costs one approval and has two legs.

Leg one, phase 1 (not run: the user's):

```
gh workflow run release.yml --ref main -f mode=rehearsal
```

Approve the `sign` job (section 3). The run ends with the draft `v<version>-rehearsal` holding the binaries,
the list, the envelope, the notices and `SHA256SUMS`. A rehearsal may be started again at any point; its
draft's files are replaced. After leg two the draft also holds the CLI files, which `attach` refuses: delete
the draft before starting the rehearsal again.

Leg two, phase 2 (not run: the user's): at a clean checkout of the commit that leg one built, run

```
scripts/release/pin.sh --rehearsal
git switch -c release-rehearsal
git add crates/lunepack-cli/prebuilt.json crates/lunepack-cli/prebuilt.sig.json
git commit -m "Pin the rehearsal list"
git push origin release-rehearsal
gh workflow run release.yml --ref release-rehearsal -f mode=rehearsal-finalize
```

`pin.sh` is explained in section 6. The run proves the pins, adds the CLI files and publishes nothing. Then
delete the branch `release-rehearsal` and the draft `v<version>-rehearsal`. The rehearsal is never merged.

## 5. Phase 1 **[user] starts, [automatic] runs**

(not run: the user's.) On `main`, at the commit A to be released:

```
gh workflow run release.yml --ref main -f mode=binaries
```

The jobs, in order: `plan` (the mode and the version, from the event and the workspace), `preflight` (the
publish dry run, the boundary check, the notices check, the workflow lint, the release-script tests, the
signing environment's settings, and a project key built into the CLI), `build` (the twenty files of the
matrix: six target ids from four build jobs) and `build-cli` (the CLI for four hosts), `assemble` (the list, the notices and
`SHA256SUMS`), `draft` (creates the draft `v<version>` with those files), `sign` (waits for your approval,
then signs the list) and `attach` (downloads the draft as stored, verifies the envelope and every file
under the CLI's built-in key, refuses any file outside the release's set and a `SHA256SUMS` or notices
file that does not match, and only then adds the envelope).

`draft` fails when a release, a draft or a tag of that version exists, so starting `binaries` again while a
draft exists fails on purpose, before anything is signed. Two signed lists for one version cannot come out of
the workflow; a deleted draft is what could bring that about (the threat model says why that matters), so
do not delete one casually.

### When phase 1 fails

By where it stopped.

- **Before `sign` has succeeded** (a rejected or expired approval, a red `preflight`, a refusal in
  `sign-list.sh` such as a secret that holds another key or damaged PEM text): nothing was signed. Fix the
  cause. When the fix needs no commit (a setting, the secret), use "Re-run failed jobs" on the same run,
  which may ask for the approval again. When it needs a commit, delete the draft by hand and start `binaries`
  again at the new commit.
- **After `sign` has succeeded** (a failed `attach`): use "Re-run failed jobs" on the same run, so `attach`
  uses that run's envelope. Never delete the draft and start again: the first run's artifact is already a
  signed list for that version. When `attach` cannot pass on that run, the next attempt takes a new
  version.

## 6. The pin commit and the tag **[user]**

The CLI of a version carries the list of its own binaries, so the list has to be committed before the tag.
At a clean checkout of A (not run: the user's):

```
scripts/release/pin.sh
```

It refuses unless the work tree is clean, the list and the envelope download from the draft `v<version>`,
the CLI's own parser accepts the list, its version is the workspace version, its `source_commit` is `HEAD`
and `HEAD` is on `origin/main`, its `rehearsal` flag is false, and `prebuilt verify` passes under the
built-in key of the CLI built from this checkout. Only then does it copy the two files to
`crates/lunepack-cli/prebuilt.json` and `crates/lunepack-cli/prebuilt.sig.json` and print what to do next.
It holds and reads no key, and commits, pushes and tags nothing. By hand, in this order:

1. Commit exactly those two files: the pin commit B. Nothing else may change on `main` after A until the
   tag.
2. Land B on `main` (a push or a merge; a squash merge makes a new commit with the same two-file diff and
   is fine).
3. Only then tag the commit that is on `main`: `git tag v<version> <that commit>`, then
   `git push origin v<version>` **(cannot be undone: a pushed tag starts phase 2, and a signed list cannot
   be withdrawn)**. A tag on a local commit that never landed fails the tag run.

Phase 2 **[automatic]**, no approval: `finalize` proves the pins (`scripts/release/verify-pins.sh`: the
committed files are the draft's, byte for byte; A..B changes exactly the two files; every file matches and
the draft holds no other file, `SHA256SUMS` and the notices included; the
envelope verifies under the key built into the CLI at B; the CLI's own state is `pinned`), builds the CLI for
four hosts, adds the four files to the draft and publishes it.

If the tag run fails after the pin commit has been pushed, the signed list is in public view and cannot be
withdrawn: the next attempt takes a new version. What a failed run costs before that: nothing is public
while the draft is unpublished, and the fix is a new commit, so phase 1 is redone at a new A, the draft and
the tag are deleted, and the version is reused only if the tag rule lets you delete the tag.

## 7. After the release **[user]**

In this order. The CLI on crates.io is permanent and pins hashes that the release page has to serve, so the
page is checked first.

1. The GitHub release is public (phase 2 did that).
2. With the CLI built at the tag, for every target of the list (`linux-x86_64`, `linux-aarch64`, `windows-x86_64`,
   `macos-universal`, `macos-aarch64` and `macos-x86_64`), against the real release (not run: the user's):

   ```
   lunepack prebuilt fetch --target <target> --out <dir>
   ```

   Each must succeed. The command refuses in every state but `pinned`, so a success is also the proof that
   the CLI's list is signed by the key it carries.
3. Only then, from a clean checkout of the tag, with your own crates.io token **(cannot be undone: a
   published version can be yanked, never removed)**:

   ```
   cargo publish --workspace
   ```

   (not run: the user's.) It publishes the ten crates of the publish set in dependency order; the crates of
   one release require each other with `=`, so they go out together. The runtime, the service, the stubs
   and the two UI crates are not published; they come from the release page or a checkout.
4. Update the sentence under "Status" in `README.md` (it says that nothing has been published) and the
   heading of the version in `CHANGELOG.md`, and raise the version as section 2 describes.

## 8. Replacing the key

### 8.1 Rotation **[user]**

A rotation is a code change: the source is the anchor, and there is no signed chain from the old key to the
new one. Make a new key as in section 1.1, replace the secret (`gh secret set LUNEPACK_PROJECT_KEY
--env release-signing ...`, as in 1.3), and make one commit that

- appends the new key set to `PROJECT_ROOTS` with the next version (the earlier entries stay),
- updates the table of `SECURITY.md` (the old rows become `retired`, the new ones `current`),
- raises the version, and
- truncates `prebuilt.json` and `prebuilt.sig.json` to zero length (a list signed by the old key beside a
  new current key is the state `inconsistent`).

Two rules, each with its reason:

- **The code change and the secret change belong together.** With the old secret under the new constants the
  signing job refuses, because the CLI verifies what it signed under its built-in key, and nothing is
  signed. With a signer that is not in the key set the CLI says so and writes nothing; here, a key made for
  the session against the key set of another:

  ```
  $ lunepack keys gen keyvol/other.lpk 2>/dev/null
  lunepack prebuilt sign --list prebuilt-0.1.0.json --out prebuilt-0.1.0.other.json \
      --sign file:keyvol/other.lpk --trusted-key "$PUBLIC"
  ls prebuilt-0.1.0.other.json
  public: 849ca773...0810
  id: 34b67026...4b47
  error: the signed envelope does not verify under the key set (nothing was written): 0 of 1 required distinct keys verified; the key set expects key id(s) d589939d...04fc (threshold 1); signed by key id(s) 34b67026...4b47
  ls: prebuilt-0.1.0.other.json: No such file or directory
  ```

  (The ids are public; `$PUBLIC` is the public key of the key the set was made from.)
- **A list of an older release is checked under the key set that signed it.** `prebuilt verify
  --root-version <n>` checks it under the earlier built-in set `n` and says in its result that the set is
  retired. An older CLI checks a newer release only with `--trusted-key <public key>`, reading the key from
  the table of `SECURITY.md` or from the source of a newer release. A CLI with no key set built in
  refuses both and says so:

  ```
  $ lunepack prebuilt verify --list prebuilt-0.1.0.json --sig prebuilt-0.1.0.sig.json --root-version 1
  error: this CLI has no project key built in; name the keys with --trusted-key
  ```

  (This is the CLI of this repository, which has no key set yet; with one, `--root-version 1` works.)

### 8.2 A leaked key **[user]**

Replace the secret and rotate at once (section 8.1), publish a security advisory on the repository, and
release. What the leak allows and does not is in the threat model: with the key, someone can sign a list for
any version that verifies under every CLI that has the key built in, when a person checks a download by
hand; they cannot change what any published CLI pins, and they cannot publish on the project's release page,
which needs write access too. The signature has no expiry and there is no revocation channel: the
rotation, the advisory and a release are the whole answer.

### 8.3 A lost key **[user]**

The secret deleted and no copy kept: the same rotation. Nothing else is lost; the key was never needed
outside the workflow.

## 9. What cannot be undone

| Step | Why |
| --- | --- |
| Making the key and putting its public half in a CLI that is published | the key is a constant in every published CLI of that version, and on crates.io; the back-out is a rotation |
| Pushing the pin commit and the tag | the signed list is public; a failed tag run is followed by a new version |
| Publishing the GitHub release | the files are public, and a CLI of that version pins them |
| `cargo publish` | a version on crates.io can be yanked, never removed |

Reversible: the environment and the secret (delete either; a secret cannot be read back, only replaced),
the constants before a CLI that carries them is published (revert), a rehearsal (delete the branch and the
draft).
