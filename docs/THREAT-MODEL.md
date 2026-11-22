# Threat model

Status: **draft**, awaiting approval together with `docs/FORMAT.md`.

What lunepack's update and install path defends against, and what it does not. The format rules
referred to here are in `docs/FORMAT.md`; the decisions in `docs/DECISIONS.md` (D7, D17, D21, D24,
D33, D34, D35, D36 to D41, M3-D1 to M3-D13, M4-D1 to M4-D23, M6-D1 to M6-D12, M7-D1 to M7-D22, M8-D1 to M8-D20).

## Assets

- **Code that runs on the user's machine**: the installed app tree, the runtime, the UI binary and
  the Windows stub. The main asset: an attacker who can place bytes there runs code as the user (or,
  for a per-machine install, as every user).
- **Trust state**: the compiled-in root, the persisted highest root version, key-set version and
  feed seq per channel (anti-rollback floors), and the install-state record (current, previous,
  pending and bad versions).
- **Signing keys**: the offline root keys and the online release keys. Only public keys ever reach
  clients.
- **Privacy**: the install id and the rollout bucket (D24). They are never sent.
- **Availability**: the ability to receive security updates in time.

## Trust anchors

- The trusted root compiled into the app, or a higher root version the client verified before.
- Everything else is derived: root rotations (signed by the old and the new root), the key set
  (signed by the root), the feed and manifests (signed by release keys), packs and frames (bound by
  SHA-256 in the signed manifest).
- The first download of an installer is outside the format: it is protected by OS code signing and
  the user's choice of source, not by lunepack. After that, the installer verifies its own payload
  against its compiled-in root like any update.

## Attacker classes

### 1. Network or hosting attacker

Controls the network path or the static host (a compromised bucket, CDN or mirror), but holds no
signing key.

Stopped:
- **Modified or forged documents**: every document's signature is checked over PAE(type, payload)
  before its payload is parsed; packs and frames are checked by SHA-256 before use.
- **Mix and match**: the key set is bound to the app id and root version, the feed to the app id and
  channel, the manifest by size and hash from the feed and to the app id, version and target.
- **Rollback and replay**: floors on root version, key-set version and feed seq per channel; an old
  but validly signed document below a floor is rejected. The client never downgrades. A first
  install has no floors yet, so the bootstrap tree's own version is its floor: a replayed, still
  unexpired feed whose newest release is older than the tree the user ran installs nothing
  (`no_release`), and the bootstrap's own version is allowed (M5-D8).
- **Endless data**: every download is capped by a signed size (manifests by the feed, frames and
  packs by the manifest) or by a fixed cap (root and key set 64 KiB, feed 8 MiB).
- **Parser attacks before authentication**: the only code that sees unauthenticated bytes is the
  size check, the strict JSON pre-pass, the envelope parse and base64 decoding: pure safe Rust,
  fuzzed. Payload parsers, frame descriptors and decoders run only on authenticated bytes.
- **Tracking**: no identifying query parameters; the rollout bucket is computed locally.
- **Hostile responses to a Range request (M4)**: see "The download path" below. A short, long,
  mislabelled, re-encoded or mixed-version body is refused or caught by a hash before anything is
  placed.

Not stopped:
- **Freeze**: withholding new documents (feed, key set, a root rotation) keeps clients on the
  current version. Bounded by expiry: a feed past `expires` (default 90 days) or a key set past its
  `expires` gives "no update" plus a reported error, so the freeze becomes visible. Without
  `expires`, a freeze is unbounded and silent.
- **Denial of service**: refusing to serve, or serving garbage, blocks updates; it never installs
  anything.
- **Learning what a client fetches**: the attacker sees which documents and ranges are requested.

### 2. Leaked release key

The attacker holds a key listed in the current key set. With a release threshold above 1 one key
is not enough; the rest of this section assumes the attacker meets the threshold.

Stopped:
- After the root signs a new key set without the key, every client that has seen it rejects
  documents signed by that key, and the key-set floor stops the old key set from coming back. No
  app update is needed.
- The key is only accepted inside its `not_before`/`not_after` window for feeds.
- A release signed with the leaked key alone cannot also carry the publisher's OS code-signing identity,
  which the key does not hold. Under `enforce`, an installed app whose update configuration sets the
  publisher-continuity policy refuses a release signed by another identity, unsigned or ad hoc, and marks it
  bad (section "OS code signing and publisher continuity (M9)" below). This is a second barrier for apps
  packed with OS signing, not a substitute for revoking the key.

Not stopped:
- Until clients fetch the revoking key set, the attacker can sign a feed and manifests and ship
  arbitrary code to clients they can serve (with hosting control, or with network control over a
  client). An attacker who also controls hosting can withhold the revoking key set; that freeze is
  bounded only by the key set's `expires` and the key's `not_after`. Short windows and an `expires`
  on the key set limit this.
- A leaked key can raise the feed `seq` floor to a huge value, so the publisher's next feeds must
  exceed it.

### 3. Leaked root key

The attacker holds root keys meeting the root threshold.

Not stopped: the attacker can sign a key set with their own release keys and a root rotation to a
root they control. A client that accepts the rotation persists the higher root version, which then
wins over the compiled-in root, so an app update with a new compiled-in root does not recover such
a client; only a reinstall does.

Mitigations, not prevention: keep root keys offline, use an m-of-n threshold above 1 so one leaked
key is not enough, and rotate promptly (a rotation the publisher signs first raises the floor for
clients that fetch it before the attacker's).

### 4. Local process running as the same user

Not stopped for a per-user install: such a process has the same rights as the app. It can modify
the installed tree, the state record (including the anti-rollback floors and the bad-version list)
and the app binary with its compiled-in root. lunepack does not try to protect a per-user install
from its own user.

Stopped: it cannot alter a per-machine install or its machine-scope state (written only by the
privileged engine in admin-only locations).

The library's own files are in the same position (M4). For a per-user install the state directory,
the download cache and the version trees are writable by that user, so such a process can:
- rewrite or delete the install-state records, including lowering the floors or emptying `bad`
  (FORMAT.md 12). The records are checksummed against a torn write, not authenticated; the checksum
  is no defence against an attacker who writes a whole record. Not stopped, like the tree itself;
- plant or edit cache files. This gains nothing beyond what it can already do: a complete cache file
  is named by its SHA-256 and is hashed again before use (and a frame again by `decode_verified`), so a
  planted file fails the hash, is refetched, and at worst costs the user a download;
- hold or release the updater lock, which only gives `Busy` or lets two operations race on files each
  of which is checked by hash. A race can fail a stage; it cannot place unverified bytes.

### 5. Local process running as another user

Stopped:
- Per-user installs live in the user's own profile, which other users cannot write.
- Per-machine installs: the privileged engine (on Windows, the update service, "Windows per-machine (M10)"
  below) takes only the bytes a client streams over its pipe, copies them into an admin-only staging
  directory, and only then verifies the whole chain (copy, then verify: no time-of-check/time-of-use
  window). It never opens a file in a user's namespace, never calls an impersonation API, never follows a
  caller-supplied path or URL, never runs payload code before verification, and never acts for an app id
  other than its own install's.
- The library never writes the machine install's state (M4, FORMAT.md 12.6): it reads the machine
  record and the tree through the layout, and writes only this user's `install-counters` records,
  cache and lock in the user's own directories. Another user cannot lower this user's floors, and
  this user's counters cannot lower the machine record's: the key-set version and the feed `seq` of a
  check are the higher of the two. The **root** is never taken from a user's record (M4-SEC-obs1,
  M10-D17): it is the machine record's, or the installed tree's own configuration's. A counters record
  whose install id differs from the machine record's stops the load.

Not stopped: denying service to other users' updates by holding resources, within OS limits.

### 6. Malicious publisher (out of scope)

The publisher's signature is the definition of an authentic release; lunepack cannot tell an
honest release from a malicious one signed with the right keys. OS code signing and the optional
publisher-continuity check (the installed and the candidate binaries share an OS signing identity)
detect a change of publisher identity, not malicious intent.

## Decoder exposure (Revision 2)

The compression adapter uses `lzma-rust2` with its `optimization` feature, which contains unsafe
code and asm (D17, D34). That exposure is bounded by the format: the decoder sees only frames whose
SHA-256 matched the publisher-signed manifest, and only after the descriptor (codec id, dictionary
sizes at most 16 MiB, BCJ2 sub-stream lengths) passed the pure-core checks. Feeding the decoder
crafted input therefore needs a release key (class 2) or the publisher (class 6). The output is
capped at the signed size and checked against the signed file hash before placement.

The client keeps that order in memory (M4-D11). The staging engine reads exactly the signed `length`
bytes of a frame into memory and `decode_verified` hashes those bytes and decodes the same buffer, so
the decoder never reads bytes that were checked earlier and re-read from a file an attacker could
change in between. A frame that does not hash right is never decoded, whether it came from the cache,
a Range response, the full pack or the current tree.

## The UI process is untrusted (Revision 2)

The installer and update UI is a separate process (D35). The engine (runtime, installer bootstrap
or privileged engine) owns every decision and every file operation; the UI only renders the
engine's events and returns the user's choices. The engine treats those choices as untrusted
input: it validates them against what the verified manifest and the install scope allow, and no
outcome of install, apply, confirm or rollback depends on the UI being present, alive or honest.
The UI never runs elevated, so a fault in the GPU or window stack cannot act with elevated rights.

What M6 builds, and what it does and does not defend (classes 4 and 6 excepted, as everywhere):

- **Frames from the UI are untrusted input to the engine** (M6-D2). A length over 1 MiB is refused
  before any allocation; the body is strict JSON with a closed set of types and no extra, missing or
  duplicated member; the first frame must be a hello with the engine's own build id. After that
  the only things the UI can say are an answer to the question that is open (its id, and a value
  from that question's set), a cancel while one is allowed, and the answer to the engine's liveness
  probe. The engine applies a choice only after its flow reducer accepts it, and a choice carries no
  path, name or text: the one index it can carry (the leftover to show) is checked against the list
  the engine itself sent. So a UI that lies, floods, stalls or is replaced by a local process
  can cancel a question that was asked, accept one, or be ignored, and nothing more. It cannot
  choose a scope, a location, a version or a file.
- **The UI cannot block the engine.** Every write to it goes through one bounded queue and one
  writer thread, and a stalled write, an unanswered probe (15 s), a missing hello (20 s) or a UI
  that will not exit after `Close` (5 s) ends in the engine killing its own child and finishing
  headless; no engine thread is waited for without a bound. A UI lost at a question before any
  change is a cancel, never a proceed (M6-D5). A local process that kills the UI, or that fills its
  pipe, can therefore stop a window but not an install, and no more than it could by killing the
  installer itself.
- **What the UI renders comes from the signed package.** The app's name, publisher, version and
  icon come from the signed update configuration (FORMAT.md 13.4, control characters refused) and the
  location from the engine's own path rules. They are drawn as text, ellipsized, and the icon is a PNG
  decoded within 1024 by 1024 pixels and 16 MiB (a bad or missing icon is a monogram, M6-D11); a
  malicious publisher is out of scope (class 6), but a bug in the text or PNG path is a bug in a
  process that holds no key, no token (it is removed from its environment) and no way to change an
  outcome.
- **The UI process is started only from the runtime's own directory** (never through `PATH`, `current`
  or a link, and with a fixed argument and a null error stream), so a UI is as trusted as the signed
  tree that holds it; a same-user process that can replace it can already replace the runtime
  (class 4). Its build id must equal the runtime's.
- **The GPU and window stack is attack surface that is kept out of everything that matters.** LuneUI,
  `wgpu`, `winit` and AccessKit load graphics drivers and display libraries at run time and carry
  `unsafe` code; the boundary check lets only `lunepack-ui-luneui` and `lunepack-ui` reach them, so
  the runtime, the stub, the facade and any elevated process never link them (D17). LuneUI is the one
  git dependency, pinned to a commit the boundary check names (D39); updating the pin is a reviewed
  change of that constant, and a lock entry from another source or commit fails the check. A broken
  driver, a missing display or an old glibc ends the UI with a typed exit code and the install goes
  on headless (D36).
- **Opening a folder** (M6-D10) is the one thing a UI answer makes the engine start: `xdg-open` on the
  parent of a leftover the uninstall itself reported, without a shell, at most once a second.

## Setup files (M6)

A Linux setup file (`docs/FORMAT.md` 14, `lunepack setup`) is the release's runtime followed by the
signed payload, so one file installs offline. It adds a path that verifies a release with no feed, and
it runs code before the user has agreed to anything, so the rules below carry the weight.

- **The file is its own trust anchor, like any installer's first download.** The trailer is not signed;
  its root is the anchor of that install, as the root compiled into an installed tree is. Someone who
  can change the file can replace the root and the payload together, so what protects the file in
  transit is the same as for every first download: the user's choice of source and OS code signing
  (below, Trust anchors), not lunepack. What lunepack adds is that a file whose parts, hashes or
  signatures do not fit together is refused before anything is shown or written, and that a trailer
  that is present but malformed never falls through to the ordinary runtime (exit 7).
- **The trailer is parsed as untrusted input.** Only the last 4096 bytes are read; the body is strict
  canonical JSON that must re-encode to the same bytes; every part must be non-empty, 8-aligned,
  inside the file and before the trailer, not overlap another, and fit the caps of FORMAT.md 4; an
  unknown format is a newer format. No length is trusted before it is compared with the file's size.
- **The offline verification path** (M6-D4) is the chain of the feed path with the feed taken out: the
  key set under the trailer's root, then the manifest under that key set's release keys that are valid
  now at its threshold (the signatures take the place of the feed's hash binding, so the key windows
  count), its app id equal to the key set's and its version and target equal to the trailer's, then the
  pack against the manifest's size and hash, then the update configuration read from the pack through
  its signed frame (frame hash before the decoder, decoded size and hash after) naming exactly that
  root. Frames are copied into the cache only after their own hash matches, and each is checked again
  when the tree is staged. No byte of the payload reaches a decoder, a trusted type or the disk tree
  before its signature or hash check. The runtime inside the setup file is the file itself; the one
  other executable it reads out, the UI, is a signed frame like any other file.
- **Freshness is the key set's and the release key's, not a feed's.** A setup file has no feed, so it
  has no feed expiry, no sequence and no rollback floor: it installs the one version it carries, and
  the floors it commits are its own key set's. It stops installing when the key set's `expires` passes
  or its release keys' windows end (FORMAT.md 14.2); nothing re-signs an old release, so a publisher
  rebuilds setup files from a current one. The cost: a revocation by a newer key set does not reach a
  setup file already in someone's hands, so a leaked release key (class 2) stays usable in setup
  files until its window ends, and a short window is the defence; once installed, the app takes
  the next key set from the feed and the revocation applies from then on.
- **The UI's directory** (M6-D7) is made fresh by the setup (a random new name under the per-app cache,
  mode 0700, files created with `create_new`, nothing existing reused or followed), receives the UI only
  from the verified frame and is removed when the run ends. An earlier run's directory is removed only
  when its marker names this app and a process that is no longer running, so a directory a local
  process planted without that marker stays. The cache belongs to the user (class 4 applies as to
  everything else the user owns).
- **With a window, nothing is installed before the user answers the welcome question**, and cancelling
  (or losing the window there) leaves nothing but the removed temporary directory; with no window the
  question takes its headless default, so a setup file run with `--silent` installs. A setup file installs into the per-user root only, and an existing install of
  the app is refused (`already_installed`, 23), as is a root that is not empty or not lunepack's.

## Packager and signing keys

`lunepack` (`docs/CLI.md`) holds the signing keys' reach, not the keys' custody: it is run by the
publisher, on the publisher's machine or CI runner, and trusts that machine. What it does and does not
defend is below. Everything it writes is a document the format already authenticates, so a flaw here
is a publisher-side compromise (classes 2, 3 and 6), never something a client has to trust.

- **Key files at rest.** A key is Ed25519 as PKCS#8 PEM. `keys gen` creates it with `create_new` and
  mode 0600 on Unix; loading refuses a file readable by group or others. On Windows the file
  inherits its directory's ACL, which lunepack neither sets nor checks. Any process of the same user
  can read the file: lunepack does not protect keys from their own user (class 4). Keep root keys
  offline and out of CI; give CI only a release key with a short window.
- **An env signer.** `env:<VAR>` reads a PEM from the environment. The value is visible to every
  process of the same user that can read the process environment (on Linux, `/proc/<pid>/environ`) and
  is inherited by every child the CI job starts. Prefer a file or a command signer where that matters.
- **A command signer.** For HSM, KMS or a signing service. The message goes to the command's stdin and
  the signature comes back on stdout; lunepack never sees the key. The argv is visible to other
  processes of the same user, so it must not hold secrets: pass them in the command's environment. The
  command's stderr goes to the terminal untouched, so a noisy command can print what it likes.
- **Signatures are verified before use.** A command signer's output is checked against the configured
  public key before it is placed in a document; a wrong, malformed or oversize answer fails the
  command. A key is only accepted if it is a valid, non-small-order Ed25519 key, and only if it is in
  the root or key set it signs for, inside its window, and counted once toward the threshold.
- **Nothing secret is printed.** No command prints, logs or puts in an error a private key, a PEM line,
  an environment value or a config value. Config errors name the file and line and never the text
  of the line; a bad `SOURCE_DATE_EPOCH` is named, not echoed. An integration test scans stdout and
  stderr of every command for each generated key in raw, hex (both cases), base64 (both alphabets, with
  and without padding) and PEM-line form. It cannot see a secret that a command signer's own stderr
  prints, or one the operator passes in an argv.
- **Every output is verified before it is placed.** Each command builds its documents, then checks them
  with the verifiers a client uses (root walk, key set, feed, manifest, the pack against its signed
  size and hash, every frame through the decoder), and only then moves files into place (temporary file
  in the destination directory, then rename). `pack` places the pack before the manifest and never
  overwrites either; feeds and key sets are replaced atomically. A bug in the packager's encoder, layout
  or writer therefore surfaces as a failed command, not as a release that clients reject.
- **Input is treated as the publisher's own files.** `pack` copies the input to a private temporary
  directory first, hashes the copy, and re-checks each file's hash when it is read for encoding, so a
  file that changes during packaging is an error. It refuses special files (fifo, socket, device),
  checks symlinks against the format's rules and does not follow them. It does not defend against a
  hostile build output: a malicious binary in the input is packaged as is.
- **Revocation is guarded.** `keys set` and `keys rotate-root` refuse to leave a feed that `verify`
  would reject unless told to; no writer reads a feed it cannot verify (so a forged `seq` or release
  list in an edited feed file never enters a new feed); every release a written feed lists is
  re-verified in full. A feed's `seq` is not secret and not protected from a writer holding the
  threshold of release keys: see the leaked-key class above and the `seq` = 2^53-1 limitation in
  `docs/CLI.md`.
- **Replayed older documents (S1, M3-R2-D1).** The writers build on the previous feed and `keys.json`
  in the release directory and read them with time checks skipped, so a class 1 attacker who puts back
  a genuine older document there (the publisher fetched the directory from the host it can write to)
  would have its releases, rollouts, keys, windows or threshold re-signed with a fresh `seq` or version
  and no expiry to reveal it. The defence is the publisher state file (`docs/CLI.md`), kept with the
  config and outside the release directory: every writer refuses a previous document older than the
  recorded root version, key set version or feed `seq`, and one the file has no record of, unless the
  operator overrides (`--allow-older-previous`, `--trust-release-dir`); `keys set` never carries over a
  threshold the state does not vouch for, and prints what it changes. Deletion is treated as the
  oldest replay (F5, S2): a recorded `keys.json` or root that is missing is refused, and only
  `--allow-older-previous` builds without it, with `--threshold` required, so deleting `keys.json` can
  no longer yield a version-1 key set with a default threshold of 1 and a record lowered to match. No
  writer lowers a recorded value without that override. A removed feed is the one document that may be
  missing (the revocation fallback, M3-R1-D1); its restarted `seq` must still exceed the record. After an
  operator lowers the record with the override, genuine documents between the new and the old recorded
  values are no longer recognised as replays, so restore the release directory from the publisher's own
  storage rather than override where possible. Writers trust the release
  directory's previous documents for freshness only as far as the state file vouches: without it (a
  lost file, or a run with `--trust-release-dir`), the directory must come from the publisher's own
  storage, never from the public host. The state file is not secret but must be kept from the same
  attacker; one who can edit it and the release directory both can still roll the writer back.
- **The key set's extra minutes.** Revoking in two moves leaves the old key in the local `keys.json`
  between the moves. Nothing is uploaded between them; if the publisher uploads after the first move,
  the old key is still accepted by clients until the second.

## The download path (M4)

The client's fetch and staging code adds untrusted input beyond the signed documents. Every item
below is checked before it can influence a file placed in a version tree.

**Response headers, Range responses and redirects.** A transport reports every header (names
lowercased, values as raw bytes, duplicates kept) and core applies one set of rules to all
transports (M4-D9), failing closed:
- at most one each of `content-range`, `content-length`, `content-encoding`, `etag` and
  `last-modified`; a duplicate fails;
- a `206` needs a `Content-Range` that matches `bytes <first>-<last>/<total>` exactly (lowercase
  unit, digits only, at most 16 digits, values at most 2^53 - 1), whose range equals the one
  requested and whose total equals the signed pack size; `*`, unsatisfied-range forms and any
  mismatch are an error, so a host cannot hand over a different window of a different file;
- `content-encoding` absent or `identity`; `Accept-Encoding` is never sent and no coding is decoded,
  so a compression layer cannot change the bytes between the host and the hash;
- `If-Range` carries a strong ETag or the Last-Modified value; if the file changed (or the host
  ignores `If-Range`), the final hash catches the mixed file, the part is deleted and the download
  restarts once from byte 0;
- a transport follows at most 5 redirects and returns the final response. A redirect changes where
  bytes come from, never what they must hash to: documents are verified by signature and artifacts
  by the signed SHA-256 and size, so a redirect to a hostile host (class 1) gains what that class
  already has. The default transport sends only `User-Agent: lunepack`, `Range` and `If-Range`:
  no app id, version or install id (D24).

**Cache files.** The cache holds frames and packs under their SHA-256 and `.part` files with a small
strict-JSON sidecar (the validator and a hash of the URL). All of it is local input of class 4. A
complete file was hashed when it was finished and is hashed again when used; a `.part` longer than
its signed size is deleted; a sidecar that is missing, does not parse or names another URL is ignored, so the part is
resumed without `If-Range` and the final hash decides.
Documents are never cached, so the floors alone protect them.

**State records.** The install-state records are local input too (FORMAT.md 12). M4-D23 sets the
rule for a record that is damaged or wrong:
- a file that fails an *integrity* check (name, size cap, magic, format byte, length, checksum, or a
  payload `seq` that differs from its name) is a torn write: it is skipped and the next lower record
  is tried;
- a record that passes integrity but fails parsing or the semantic rules (or names a newer format,
  an unknown critical feature or another app id) **stops the load** and writes nothing. Its checksum
  shows a writer wrote it whole, and falling back to an older record would let one with lower floors
  win, which is a rollback.

So the load returns the newest record that was completely written, or fails; it never returns an
older one while a newer whole one exists. A commit refuses to lower any floor and reads back its own
bytes before it writes. A record from a newer build (for example after an app rollback) fails closed
with a distinct error rather than a panic.

**Absent root documents and 403 (M4-D10).** The root walk asks for `root-<k+1>.json` and treats 404,
410 and 403 as "no such root"; every other status and every transport error fails the check. The
user decided to include 403 because an S3 bucket without `s3:ListBucket` answers 403 for a missing
key, and a host that cannot say 404 would otherwise fail every check. It adds no attacker
capability: an attacker who controls responses (class 1) can already answer 404 and hide a rotation,
which is the freeze already described there, bounded by the key set's and feed's expiry.

## The Linux runtime (M5)

The per-user Linux runtime (`lunepack-runtime`, `docs/FORMAT.md` 12 and 13) adds code that deletes
files, writes outside the install root, starts processes and reads configuration from a tree. It
defends against a hostile publisher or host only through the signed manifest (the configuration is
a file of the tree, covered by its hashes), and it takes no side against the app's own user (class 4):
a same-user process can already edit the tree, the records and the desktop entry. What each piece
below adds is that lunepack never acts on a path or a name it was not given by a signed tree or
derived itself, and fails toward keeping files.

**The health token (M5-D5).** The runtime draws 32 bytes from the OS random source, puts them in
`LUNEPACK_HEALTH_TOKEN` (64 lowercase hex digits) in the environment of the one child it supervises,
and records only their SHA-256. The token is never in an argument list, an event, the log, a result
line or an error, and a facade error never shows it (the apply tests search the log for a planted
token; the command line's planted-secrets test checks every stream, M5 step 14). A malformed token is `TokenMismatch`; a matching one
is compared in constant time. Same-user processes can read another process's environment, so the
token is not a defence against class 4. It tells the record that this start was the supervised one:
a per-user install also lets a start with no token confirm the pending version (M5-D5), so the token
protects nothing a local process could not do anyway. Per-machine installs always need it (C8): there the
token is what keeps another user from confirming or rolling back someone else's pending update.

**The attempt counter (M5-D5).** An unsupervised start of the pending version counts one attempt in
the record and the fourth rolls back, so an app that never confirms (a crash on start, or a program
that never calls `confirm`) cannot stay current. A same-user process can edit the counter, as it
can the rest of the record (class 4); a host or publisher cannot reach it. A supervised start counts
nothing, and a rollback marks the version bad, so the next check does not offer it again.

**The wait target and the processes it starts.** The applier only waits for the process the app
named (by pid and start time, so a reused pid is not mistaken for it, and a zombie counts as
exited); it never signals it. The one process it ever signals is its own child, by the handle it
got at spawn. Programs start without a shell, with arguments as separate values. The restart
arguments travel in the detached applier's argument list after `--` (M5-D14), so they are as
readable to other processes of the user as the app's own command line; the token never does.

**Deleting files (M5-D9, M5-D10).** Three paths remove files, each driven by state and each limited
to what lunepack made.
- Garbage collection removes only direct children of `R/versions` whose names are a version's
  canonical text, that are real directories (checked with `lstat` right before the removal), that
  the record does not keep (current, previous, pending, staged) and that no other process of the
  user runs from or has open (`exe`, `cwd`, mappings, descriptors; a process that cannot be read
  counts as using it). A process whose files vanish under the read (one inside its exit, or one
  whose main thread has ended while other threads run) is read through its live threads and
  re-probed for at most 200 ms: it is skipped only once it has exited or all its live threads read
  cleanly, and otherwise counts as using the tree. Any error keeps the tree. The one exception is a process the kernel denies
  inspection of by design (`EACCES` or `EPERM` on those reads: a non-dumpable process of the user,
  such as `(sd-pam)` or an ssh-agent, present on every desktop login and CI runner): counting it as
  in use would keep every tree forever, so its command line decides instead, and it uses the tree
  when `argv[0]` or an absolute argument, with symlinks resolved (a path through `R/current`
  included), lies under it (M5-D9, amended by the user's decision Q40). This is a heuristic with
  a gap: an app that is non-dumpable and was started by a relative path, or not from the tree's
  path, is not seen. The scan also misses a process that runs from a tree with
  none of those open, such as a script its interpreter has read completely; GC keeps current and
  previous, so only an older tree is exposed, and the cost is a process that loses its files.
- Uninstall derives `R` from its own resolved path, never from an argument or the state, and refuses
  unless `R` is exactly `<data home>/<app id>`, a real and canonical directory, holding a record of
  this app id, with no other process running from it. It removes the desktop entry only when the file
  holds the line `X-Lunepack-App-Id=<app id>` and the command link only when it is a symlink into
  `<R>/current/`; other files are kept and reported. Then, still under the lock, it renames `R` to a
  tombstone beside it in the data home, `.<app id>.removing-<16 random lowercase hex>`, and removes
  the tombstone without following symlinks: a link inside a tree is deleted, never what it points
  to. A cut-off uninstall so leaves `R` whole (the uninstall can run again) or gone (a reinstall
  works), never half removed (review finding F18). The tombstone's name comes from the app id only,
  never from the state, and is never an install root, since an app id begins with `[a-z0-9]`.
  Install, when its root is `<parent>/<app id>`, and uninstall, once `R` is validated, first remove
  what cut-off runs left: only real directories in the data home whose name is exactly that form
  for this app id, checked with `lstat` right before removal and removed with the same no-follow
  rule; a file or symlink at such a name, another app's tombstone or a near miss is left alone.
  This cleanup runs outside the install lock (the lock lives inside `R`); two runs removing one
  tombstone at once is harmless, and an uninstall whose own removal fails reports the failure only
  while its tombstone is still there. After an environment change (a different
  `HOME` or `XDG_DATA_HOME` than at install) the derivation no longer matches and uninstall refuses;
  a file outside `R` that lunepack made then stays. Because uninstall removes `R` whole, the first
  install takes over an existing `R` only when it is a real directory that is empty, holds a record
  of this app id, or holds nothing but a `state` directory with the lock and record files of a run
  cut off before its first record; anything else at that path (a file or symlink, the app's own data
  from before lunepack, another packaging's directory, a shared directory such as `applications`)
  is refused before the first write, the lock included. The check is in the facade's
  `Updater::install`, so every caller gets it: an installer built on the crate API sees
  `Error::ForeignInstallRoot`, the runtime's `install` mode `install_mismatch` (26). It reads `R`
  once without the lock; it guards against accidents, not against a local process racing it.
- The `current` link is derived from the record; a link or file at that name that is not a symlink
  is refused, never replaced.

**Desktop entries (M5-D4, FORMAT.md 13.4 and 13.5).** Name, comment, icon, categories and the command
name come from the signed configuration and go into a file the desktop environment reads and
executes. They are checked before anything is written and a value that does not pass is refused,
never escaped: names and comments reject controls and line breaks, the command name has a closed
character set, categories are freedesktop names, the icon must be a PNG or SVG file of the tree, and
the paths put into `Exec` and `Icon` (the install root and the entry) must contain none of the
characters that give them another meaning in the specification (quotes, backtick, `$`, backslash,
`%`, the apostrophe, controls and invisible format characters). The entry's bytes are fixed in shape,
so a hostile string cannot add a key or a line. An existing entry or link that is not ours is a
conflict, found before the first write, and nothing is overwritten.

**The update configuration's feed (M5-D16).** The configuration carries the feed the runtime
fetches metadata from, so it is checked with one rule before the first request, by the packager and
by the client: `https:`, `file:`, or `http:` only to a loopback IP literal (`127.x.y.z` or `[::1]`),
in the canonical form of the URL parser the transport uses, with no user information, query,
fragment or escape. An `http:` feed from the configuration is fetched without the environment's
proxy and without following a redirect (either would carry a plain request off the machine). A
hostname such as `localhost` is not accepted because the resolver, not the rule, decides where it
goes. The library path is unchanged: an app that builds the updater itself may use any URL, as in
M4, and the signatures and hashes protect the content on any transport.

**The command line as an input surface (D42, M5-D11).** The app-facing commands (`check`, `download`,
`startup`, `confirm`, `apply-and-restart`; `docs/RUNTIME.md`) take their argv from whatever starts
the runtime, and any process of the same user can start it with any arguments. That is no new power
over the app (class 4 can already edit the tree and the records), but the runtime must not turn an
argument into an action no signed tree allows. So:
- The parser is hand-written and closed: every option is named, may appear once and has a value of a
  fixed form; an unknown option, a repeat, an option of another command, the `--option=value` form
  or a stray word is a usage error (exit 2), decided before any lock, state read or network access.
  A framework parser is not used because its error text echoes the argument values.
- No argument supplies trust material or a location: not the trusted root, the feed, the install
  root or the tree to act on. Those come from the tree's own update configuration (`docs/FORMAT.md`
  13), which the manifest's hashes cover, and from the runtime's own resolved path. `--channel` only
  picks a channel name that passes the channel rule, from the feed the configuration names;
  `--expect-version` only names the version the caller expects, and any other one is refused, never
  taken as a downgrade; `--expect-schema` only refuses.
- `--wait-pid` names a process that the applier waits for and never signals, identified by its pid
  and start time, so a pid the system reuses is not mistaken for it. A caller that names a wrong or
  exited process can delay or hasten its own update and nothing else.
- The arguments after `--` are passed to the program the runtime starts (the new tree's entry, or
  the previous one on rollback), as separate values with no shell. They travel in the detached
  applier's argument list, as readable to the user's other processes as the app's own (M5-D14).

**Output hygiene (C4).** What a caller reads (stdout, stderr, the exit code) and what the runtime
logs must not carry what a same-user observer or a captured log could misuse, or what a hostile feed
could place there. The rule is by construction, not by redaction: the only strings in any object
come from signed documents (versions, channel names, signed relative paths), from the closed sets of
`docs/RUNTIME.md` (kinds, phases, outcomes, reasons) and from the build. No path, URL, host name,
header, argument value, install id, key, health token, file content or operating-system or network
error text reaches a stream; an error is its closed kind and its exit code, and the facade's own
error `Display` is never printed. A refused command line prints one fixed line, or, with `--json`
before any `--`, the one `error` object with no command or tree version, and exits 2 before
anything else happens. Progress is bounded (at most ten lines a second as JSON, one a second as
text), a reader that stops reading cancels the operation and cannot stall it, and the log under
`R/logs` holds the same events as the stream. Two tests hold the rule: a golden for every error
kind and event, and a planted-secrets test that runs every command, with and without `--json`, in
success and in each reachable error, and fails if a planted token, install id, feed host label or
unique path component appears in plain, JSON-escaped or hex form in stdout, stderr or the log (it
first plants one in a known output to prove the check can see it, and its failure message names the
stream and the item, never the value).

## Windows per-user (M7)

The Windows per-user install (`docs/FORMAT.md` 15 and 16, `docs/RUNTIME.md` "Windows") adds a launcher stub,
registry entries, a Start-menu shortcut, a setup file that is an executable and may be signed, a
user-chosen display name used as a folder name, and an uninstaller that copies itself to the temp directory.
Class 4 (a process of the same user) is out of scope as before: it can already edit the tree, the
records and the registry keys under `HKCU`. What the pieces below add is that lunepack acts only on
paths it derived itself or read from a signed tree, and fails toward keeping files.

- **DLL planting from the download folder (M7-D10).** A `Setup.exe` is run from a folder (typically
  Downloads) in which another program can have put a DLL with a system DLL's name, and Windows looks in the
  executable's own folder first for a DLL it does not find among its known set. Every shipped Windows binary
  (the stubs, the runtime and the UI) therefore links the C runtime statically, carries a manifest and sets
  `DependentLoadFlags` to `0x800` (static imports come from System32 only), and calls
  `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` as the first statement of `main`. Step 0 measured
  that `DependentLoadFlags` covers the static imports only and that a later `LoadLibrary` still searches the
  application's folder unless that call has been made, so both are needed. The end-to-end suite
  (`scripts/e2e-windows.ps1`, row 9; `scripts/ci/plant-dll-test.ps1`) copies the setup file, the runtime
  and the console stub into a fresh folder that also holds files named after DLLs none of them imports
  statically; the files hold garbage, so a binary that loaded one fails to start with a loader error, and the
  test requires that each starts and ends with its own exit code. This is the garbage-file form: the
  module-sampling instrument of step 0 (it saw which DLLs a process loaded, and had a working control, an
  unhardened binary that did load planted DLLs from its folder) is not part of the suite. The first run of that test found that the runtime
  and the UI loaded `cryptbase.dll` from the planted folder through a static import of `advapi32.dll`
  (resolved before `main` can call anything); both now delay-load `advapi32`, and the packager refuses a
  Windows stub, runtime or UI that imports it statically (`StaticAdvapi32`), that imports a C runtime DLL
  (`vcruntime*`, `msvcp*`, `api-ms-win-crt-*`, `ucrtbase`), or that lacks the flag or the manifest. Packing
  also checks that stamping the icon and version information kept those fields. Not covered: a DLL a
  third-party library loads by a path of its own, and the aarch64 build, which has not been run.
- **The trailer locator (M7-D11, `docs/FORMAT.md` 14.3).** A signed `Setup.exe` has its trailer before the
  certificate table, so the locator reads a second candidate end, taken from the PE headers of the file's
  own first 4096 bytes. It is fail-closed in the right direction: only a file that carries the trailer's
  magic at a candidate end can be refused (the runtime starts this way every time, so a layout that was
  refused before the magic was found would break every start), a file with the magic and a layout no writer
  makes (bytes after the table, a misaligned or overlapping table) is exit 7 and never runs as an ordinary
  runtime, and the trailer lies inside the bytes the signature covers, so flipping one byte there fails
  `signtool verify` and the setup. The end-to-end suite signs a setup file with a throwaway certificate on a
  disposable runner and checks all three claims (it installs when signed; a flipped trailer byte and an
  appended byte each exit 7). A timestamped signature is a longer certificate table at the end, which the
  locator accepts unchanged (M9 signs the setup file through the packager's `sign_installer` template; the
  timestamp service is whatever the developer's template names, and CI's throwaway signatures carry none).
- **The stub reads untrusted local state (M7-D7).** The stub runs with the user's rights and starts what the
  install record and the configuration name, so it takes `R` from its own resolved path only (no argument,
  environment variable or registry value), reads the record read only with its checksum and the
  configuration with the same reader the runtime uses, refuses a symbolic link or reparse point anywhere
  below `R` and a configuration that does not name the record's version and app, and shows a fixed message
  with no value read from the install. It cannot be made to start another app by editing the state
  without also editing the tree, which class 4 can do anyway. It carries no network, codec or UI code
  (the boundary check, `DEPENDS_ONLY_ON`), and it sets no working directory (a long one fails to start a
  process on Windows, measured, error 267).
- **Registry and shortcut values from configuration strings (M7-D3, M7-D15).** The names, version, publisher
  and file-type names come from the signed update configuration and are written into registry values and a
  shortcut. None may hold a control character (refused as an unsafe field, never written), every command
  quotes the stub's path (a folder name has spaces and non-ASCII letters), a URL scheme is checked against
  the deny-list of `docs/FORMAT.md` 13.4 and an extension against `[a-z0-9]{1,16}`, and no file type or
  scheme is made the default handler: the user's own choice and the extension's default value are never
  read or written. Each key, value and shortcut that lunepack writes carries a marker, and one without
  it is left alone and reported as a conflict, so lunepack never overwrites or removes another program's
  entry that happens to have the same name. A scheme or ProgID that another program registered per machine
  (`HKLM\Software\Classes`, read only) is a conflict too, because the per-user key would shadow it in the
  merged view.
- **A user-chosen name as a path component (M7-D15).** The display name becomes a folder name under the
  user's programs folder, so it is validated, never rewritten: at most 64 UTF-16 code units, no
  character Windows forbids, no leading or trailing dot or space (a leading dot is lunepack's own
  namespace beside `R`: tombstones) and no device name. A name that fails is refused by the packager and
  again by the install. `windows_name_ok` is the one function for the folder and the shortcut.
- **Finding an install reads other folders (M7-D16, M7-D17).** To find the install of an app id the
  runtime lists the programs folder (at most 4096 entries, else it refuses) and reads the newest record of
  each folder that holds `.lunepack\state`, read only, through the store reader and without following any
  link. It writes nothing there, never reads a registry value for this (`InstallLocation` is written for
  Windows and never read), refuses when two folders hold the app's record, and a folder that is in the
  way of a first install (a file, a non-empty folder, another program's install) is never touched: the
  install takes `<name> (<app id>)` or is refused. Under the install lock a writer first checks that the state
  directory holds no record of another app id, so two apps with one display name cannot take one folder.
- **The uninstaller's root and hand-off (M7-D5, M7-D16, M7-D21).** `uninstall` takes `R` from its own
  path, never from a registry value, and requires a real directory that is not a reparse point, whose
  canonical parent is the programs folder and which holds a record of this app. Phase 1 of the hand-off
  copies only its own executable and a regular-file UI into a new directory under the temp directory and
  deletes nothing. Phase 2 accepts `--install-root` only when it runs from such a directory (named exactly
  `lunepack-uninstall-<16 lowercase hex>`, directly under the temp directory, with a marker naming the
  same app); anywhere else the argument is a usage error before any action. Both phases check the root
  again, and a root of another app, a junction, or a root whose parent is not the programs folder is refused
  with nothing deleted. A cleanup of stale copies removes only a real directory of exactly that name form
  whose strict marker names a process that is no longer running and from which nothing runs.
- **Temp directories (M7-D5, M7-D13).** The uninstaller's copy and a setup's UI directory are created new
  under the temp directory with a marker and are removed at the end of the run when possible. The copy of
  a finished uninstall stays (a running image cannot be deleted, and a self-delete technique is a
  known malware pattern that antivirus engines watch) until a later run of any lunepack app, or Windows,
  removes it; about 16 MB per uninstalled app may stay in the temp directory until then. Nothing else
  outside the temp directory is left by an uninstall (`R`, the shortcut, the registry entries and the
  declarations are removed).
- **File deletion and antivirus locks (M7-D8, M7-D12, M7-D21).** A transient lock by an antivirus scanner or
  indexer on a file being renamed or removed is retried for at most about two seconds per operation (access
  denied, sharing violation and lock violation only; not-found and already-exists never), with the last
  error reported unchanged; the budget is shared by the steps of one removal. Garbage collection walks
  `R\app` only and removes a tree only when no process runs from it, and the leftover copy of a replaced
  stub (`.<name>.old-<hex>`) is removed only when its name has exactly that form, it is a regular file
  directly in `R`, and it is not running. A stub that cannot be replaced because it runs is renamed aside, which
  Windows allows; deleting it is refused until it exits. The uninstall releases the install lock just
  before it renames `R` to its tombstone, because every process holding the lock keeps a file under `R`
  open and would make the rename fail: the window between the release and the rename is not exclusive, but
  a lunepack process that locks in it either holds an open file and makes the rename fail (nothing is
  deleted) or finds no install. A DLL of an old tree loaded by an unrelated program could see a partly
  deleted tree; no lunepack component does this.
- **Process spawning.** The stub starts the app with `CreateProcess` and no shell, passing the command line
  through unchanged and with no job object (a job would kill the detached applier). The runtime starts the
  applier and the uninstall phase 2 detached, by path, without a shell. The runtime is a Windows-subsystem
  binary, so no console appears, whatever flags an app starts it with; the end-to-end suite checks that no
  console host child appears under it.
- **Antivirus engines.** Writing and starting executables from a temp directory (the uninstaller's copy, a
  setup's UI) resembles what droppers do. Whether Windows Defender flags any lunepack binary is not yet
  measured; the CI job `e2e-windows-defender` runs the whole suite with Defender on, proves Defender
  works with a control that must be detected, and records any detection by threat name. The answer to a
  flagged binary is code signing (M9), not an exclusion; whether Defender still flags anything once the
  binaries are signed is recorded by the same CI job.
- **Renaming the install folder** is unsupported (`docs/FORMAT.md` 16): the launcher still works from the
  renamed folder, the shortcut no longer matches the install's marker and is left alone, and updates
  report it as a conflict. Nothing is overwritten or removed that is not lunepack's.

## macOS per-user (M8)

The macOS per-user install (`docs/FORMAT.md` 17, `docs/RUNTIME.md` "macOS") moves the live app: the update
swaps a bundle in the user's Applications folder, an app dragged there is adopted, the installer is an app
whose UI starts the engine, and the packager writes disk images and archives. Class 4 (a process of the same
user) is out of scope as before: it can already edit `B`, the trees, the records and `R/bundle`. What the
pieces below add is that lunepack acts only on paths it derived itself or read from a signed tree, moves
rather than deletes, and fails toward keeping the app.

- **Swap and reconcile (M8-D3, M8-D5, M8-D16, M8-D17).** The record is committed first and the disk is moved
  to match it by renames only, so the worst a crash does is leave the next start a few renames to finish:
  the crash tests cut after every mutating call, on both swap paths, and require the same end state, and a
  state the reconcile cannot make sense of it refuses without moving anything. Every
  tree is identified by the app id and version in its own configuration, read with a size cap after each
  component was checked to be a real directory or file, and never by its name; a link or a file at `B`, a
  slot or a version path is refused, never followed; a tree of another app there is refused and left; a
  name already taken is never replaced. `R/bundle` must be absolute, plain, canonical and UTF-8, and is
  refused, not repaired, when it is not. The running app keeps working through a swap (its open files keep
  their inodes; the files it opens by path afterwards are the new tree's). A startup may finish a swap while
  an old instance runs: the old instance's own tree moves, and it is judged by where the kernel now names
  it (below). A tree that is `R/versions/<version>`, named by its own version, is an old instance of the
  install; any other copy is not the install's. A bundle the user replaces at `B`'s own path with another
  version is the replaced case (`docs/FORMAT.md` 17.4): never taken for the install, adopted only after the
  proof below, and never swapped over, because reconcile finds the current version in no tree and refuses
  rather than guessing.
- **Location rules and translocation (M8-D4).** A runtime inside a translocated app (a `nullfs` mount or an
  `AppTranslocation` path component) or on a read-only volume, and an install whose `B` is on another
  volume than `R/versions`, is not owned by the user or whose folder the user cannot write, is refused with
  exit 28 and a reason from a closed set before anything is read, written or fetched, so such a copy
  can neither fail halfway nor be updated from an image. A root-owned `B` is a machine install by ownership
  (D10) and is refused `machine_scope`, exit 17; a per-machine install on macOS is a later milestone. The facts come from `statfs`, `stat` and
  `faccessat` through `Fs::place`; the translocation test is the mount type and the path component, which are
  what the system uses. A real translocated app needs a notarized one; `scripts/macos-sign-check.sh` runs
  that row with the developer's own identity (it is not part of the gate or of CI), so until it has been
  run the refusal is correct for the system's translocation and untested against it.
- **Quarantine and extended attributes (M8-D10).** lunepack never sets `com.apple.quarantine`, never
  removes it from the live bundle in place, and copies no extended attribute into a staged tree (std's copy
  does carry it; the adapter's copy writes data and mode only), so a bundle swapped in by an update has
  none, as with any updater that does not quarantine what it downloads. The assessment the system made of
  the original install on its first launch is not touched, and an update is verified by lunepack's own
  signatures (frame hashes, the manifest under the key set under the root), not by the system's. A quarantined
  copy that the user has not yet opened never runs (that is Gatekeeper's); a quarantined ad-hoc-signed
  installer app is refused, and an installer signed and notarized through `[codesign.macos]` is what passes
  (`scripts/macos-sign-check.sh` checks the assessment).
- **Adoption (M8-D9).** A bundle dragged into an apps folder is read before it is verified, so only what is
  needed to find its configuration is read with the existing, capped parser, and nothing is executed.
  The root it trusts is the one in the bundle's own configuration: the same bootstrap model as the online
  `install` from a bootstrap tree (D25), and it grants nothing beyond what running that bundle already
  grants (the same user, the same files). It is not an authentication of who wrote the bundle: a bundle that
  passes proves only that every file is byte for byte a release signed by the keys under the root it names;
  a bundle built by an attacker with its own root passes under that root, exactly as running it would have
  run it. The configuration is itself a manifest entry, so a bundle that passes carries the configuration
  its release was signed with. Before the commit nothing is recorded as current, floors rise only from
  documents that verified, and a failure leaves the bundle alone. Adoption is limited to a bundle directly in
  `~/Applications` or `/Applications` with no live install, so a development build, a download or a copy in
  the Trash never causes a request or a record, and one install per app id per user holds. Its check of the
  tree is `verify_tree`: the set of relative paths, compared as the exact bytes the directory listing gives
  and never through a lookup, file sizes, SHA-256, exec bits and link targets, with any extra entry (an empty
  directory included) a difference and no link followed. **Case- and normalisation-insensitive volumes**
  are the point of that comparison. APFS and HFS+ look names up ignoring case, and APFS also ignores
  Unicode normalisation, so a lookup by the manifest's spelling would find a file that is not named that way;
  by comparing the listed bytes a variant spelling is a missing entry and an extra one, which fails the
  proof, and a manifest cannot hold two paths that differ only in case or normalisation (FORMAT 10.2). A file
  name under the tree that normalises to another's, or differs from it in case only, is therefore never
  verified by looking it up. This is a parser-differential focus for review. A cut anywhere in the commit
  order leaves a state the next check or start finishes (`docs/FORMAT.md` 17.5), and the only record
  that can remain is one without a current version.
- **Background launch (M8-D13).** `--background` starts the app through `open -g -n -W`. The health token
  travels in `open`'s environment, which `open` hands to the app, and never in an argument, because
  arguments are visible to every process of the user through `ps`; a test reads the process list while the
  app runs. If `open` ever stopped passing the environment, the token would not arrive, the version would
  not confirm and it would be rolled back at the deadline: fail-safe, not silent. The app, not being the
  applier's child, has no exit status the applier can read, so it is identified, never assumed: exactly one
  new process of the user whose executable path is the entry's and whose start time is after the spawn,
  within ten seconds. Zero or several (a user starting the app by hand in the window, a second instance)
  is unidentified, and an unidentified app is **never signalled**: only `open` is ended, the log says so,
  and the health deadline decides. A signal to an identified app is sent only after its pid and start
  time are read again. When the bundle's `Info.plist` cannot be read (`plutil`, bounded, no shell) or names
  another executable than the entry, the start falls back to a child start. What stays: an app that
  activates itself in code still comes to the front.
- **Links through links (M8-D20, `docs/FORMAT.md` 10.2).** A framework's `Foo` is a link to
  `Versions/Current/Foo`, itself through the link `Versions/Current` to `A`. The rule is lexical: a stack of
  case-folded names starts at the link's parent, a name that is another link in the manifest is a hop whose
  own target is resolved from its own parent and whose end becomes the stack (so a later `..` pops where
  the hop led, as the kernel's resolution would), a hop that is not last must end on a directory (the root,
  a listed directory or an implied one), a `..` with nothing to pop escapes and is refused, a hop into a link
  being resolved is a cycle, and more than eight links followed for one link (far below the kernels' 32
  and 40) is refused, so no accepted link meets `ELOOP`. The model matches physical resolution because
  stage creates only manifest entries, as real directories, files and links by their text, and no entry's
  path passes through a link; so every name that is not a link is a directory, a file or nothing, and
  every link is found by its fold key, which matches every spelling APFS accepts and is stricter than ext4. The
  bounds are linear: each link is resolved once (memoised, depth-independent results only), 200,000 links
  of eight hops took 0.36 s in a release build, measured. A test materialises 10,000 seeded trees and requires,
  for every accepted tree, that each link resolves inside the root or ends in `ENOENT` or `ENOTDIR`, never
  `ELOOP`, with two instruments checked by local mutations (no hops followed, and exact-spelling lookup)
  that each find an escaping tree. The 10-minute libFuzzer runs of the `tree` and `manifest` targets have
  not been run (`cargo-fuzz` was not installed); the committed seeds replay in the gate. Final links are now
  followed too, which refuses a loop or a chain of more than eight that earlier releases of the rule
  accepted: neither resolves, so no working app depends on one. A `windows-*` manifest still refuses every
  link before any of this. Cases a reviewer should attack: `d/s` to `..` with `l` to `d/s/x` is accepted where the old rule
  refused it (the hop ends on the root and `x` dangles inside), while `s` to `.` with `l` to `s/../x`, and
  its upper-case spelling `S`, are refused (the hop leads to the root and `..` then leaves the tree).
- **The in-use scan (M5-D9 amended by M8-D19).** On macOS the scan reads executable, working directory and
  open files through libproc and fails closed on an unreadable process of the user, with two exceptions, each
  with what it cannot see. (1) A system daemon the kernel protects shows its executable but refuses its
  working directory or open files: it is judged by what is readable, so a protected daemon that runs outside
  the tree and holds a file inside it is not seen. (2) A process whose executable file was deleted has no
  executable path to be inside the tree, so it is judged by its working directory and open files alone, and
  counts as in use only if one of them lies in the tree, or if the kernel refuses its working directory
  as well (then nothing can be told). That is what a user can see: a deleted executable that maps a library
  from the tree, with its working directory elsewhere and nothing open there, is not seen, and nor is any
  library mapped from the tree by a process that has no file open there. A consequence for an interrupted
  garbage collection or uninstall: when the removal took the main executable first, the app still running
  from it, with working directory `/` and its frameworks only mapped, is judged not in use, so the resumed
  removal goes on; before M8-D19 it failed closed. Q103 accepted that. A read that fails on a process that
  is starting or ending is re-read up to three times, ten milliseconds apart, and a process that has
  meanwhile ended is not in use; one still unreadable is in use. A process that forks while the scanning
  process holds a descriptor open under the tree inherits it until its exec and is counted, rightly.
- **The installer's reversed channel (M8-D7, M6-D1, M6-D5).** In the installer app the UI is the main
  executable and the runtime is its child over the UI's own streams, the reverse of every other flow. The
  runtime treats every message from its parent as untrusted exactly as it does a child UI's (the flow
  reducer decides what is valid and what a choice may be), never signals its parent, and finishes headless
  if it is lost: a parent lost before any change cancels, after the outcome the outcome stands (Q51). The
  UI starts the runtime from its own resolved path only (the runtime must be a sibling regular file, not a
  link) with the one argument `--ui-stdio`, so nothing the user types reaches the runtime's command line.
  Its standard output carries frames only, so no result or event text can be taken for one. The payload is
  verified before anything is shown or written, from the trailer's root, as a setup file's is (this app is
  no more trusted than a setup file: an attacker who can replace it can already run code as the user). A
  `.dmg` is read-only, so the installer cannot write itself and its own location is not judged; only the place
  of the new bundle is. The installer app carries the bundle seal and the notarization ticket only when the
  packager signs it (`[codesign.macos]`, M9); without that section it is unsealed and launches
  unquarantined here.
- **Process spawning and generated text (M8-D6, M8-D11, M8-D12).** The runtime and packager start `open`,
  `plutil`, `osascript` and `hdiutil` by absolute path, with an argument vector and no shell, and each run is
  bounded in time (the alert gives up after 120 s and its process is killed shortly after). The alert's
  script is fixed and the title, text and kind arrive only as arguments, so no string can change what it
  does. The helper app's `Info.plist`, the installer's `Info.plist` and the LaunchAgent plist are written
  from the app id, name and entry of the signed configuration with XML escaping of every string, no value
  with a control character, and a deterministic byte layout; the LaunchAgent is only written (atomically,
  mode 0644, never loaded, so it takes effect at the next sign-in), replaced or removed only when its
  `Label` is the app's, and refused when `~/Library/LaunchAgents` is a link or the entry is a link or
  another program's file.
- **Deletion (M8-D5).** There are two deleters. Garbage collection removes only direct children of
  `R/versions` named by a kept version's text and checked with `lstat` just before, never `B`, the slots or the
  pointer, and only when no process runs from the tree. Uninstall removes `B`, then `R`, then the
  LaunchAgent: each by one rename to a tombstone (`.<app id>.removing-<16 hex>`, in `B`'s folder and in the
  data home) and then the tombstone; it requires `B` to be exactly what `R/bundle` names, `R` to be a
  canonical real directory holding this app's record, no process to run from `B` or from any tree in `R`, and
  every check to pass before the first removal. A tombstone of an earlier cut-off run is removed at the next
  uninstall by exact name form and without following a link. A foreign file next to `B`, another app's
  LaunchAgent and the rest of the apps folder are never touched.
- **The packager's outputs (M8-D8, M8-D9).** `pack` never modifies a bundle that holds a code signature: it
  packs it unchanged when every file it would place is already there byte for byte, and otherwise refuses,
  naming the path. The installer app and the `.zip` are built from bytes read out of the pack through their
  signed frames, so nothing unverified reaches them, and written only where nothing exists. The `.zip`'s
  entry names are manifest paths (no `..`, nothing absolute, FORMAT 10.1) under the bundle's own name (no
  `/`), and no entry's path passes through a link entry (FORMAT 10.2), so an extractor that writes entry
  after entry has no link to write through. The writer has no ZIP64, no extra fields, no encryption and no
  data descriptors, so a reader's parser has little to differ on, and it makes the same bytes each time.
  The `.dmg` is made by the system's tool and signed, notarized and stapled by the packager's templates
  when `[codesign.macos]` is configured (M9).
- **Not covered here.** Gatekeeper's, App Management's and background-item prompts and the focus of a
  relaunched app are what only a person can see (`scripts/macos-user-check.sh`); notarization, stapling and
  translocation of a notarized app are what `scripts/macos-sign-check.sh` shows with the developer's own
  identity; a per-machine install is M10 and M11.

## OS code signing and publisher continuity (M9)

Two things were added in M9: the packager signs releases and installers with the developer's own tools,
and a client can refuse an update signed by a different OS code-signing publisher than the installed one.
Neither replaces the release signatures of the format; OS signing is what the platform (Gatekeeper,
SmartScreen) judges and what lunepack compares between versions.

**Publisher continuity.** The installed version's update configuration sets a policy (`off`, `warn`,
`enforce`, FORMAT.md 13.2, RUNTIME.md "Publisher continuity"). It stops an attacker who holds the release
keys (class 2) but not the publisher's OS signing identity from shipping a build under another identity or
none. It does not stop:
- a DLL signed by another trusted publisher, added to a Windows release by a release-key holder: every
  other PE file of the candidate only has to pass `WinVerifyTrust` under *any* trusted publisher, because
  lunepack's prebuilt runtime and third-party DLLs keep their own signatures (M9-D8);
- non-PE files on Windows (scripts, data, a `.bat` an entry later starts), and anything on macOS that the
  bundle's signature does not seal, or on Linux (no OS check, `not_applicable`);
- an app that is unsigned or ad-hoc signed, or an install made before it was signed: with no baseline
  (`installed_unsigned`) `enforce` proceeds and reports, so enforcement starts at the first signed install;
- a first install, an offline install from a setup file, an adoption, and rollbacks: there is no installed
  and candidate pair;
- an attacker who holds the publisher's OS signing identity as well as the release keys: the build is then
  genuinely signed by the same publisher, and only revoking both helps.

*Verdicts are an allowlist.* An adapter answers `same`, `different` or an `unsigned`/`invalid` code only for
the operating-system statuses the design lists; every other status, and every file error while the tree
is walked or opened (a sharing violation, a scanner's lock, access denied, an I/O error), is `os`. `os`
refuses under `enforce` and marks nothing, so a local fault can never blacklist a genuine release for
good; only a definitive statement about the candidate's own bytes or signature marks a version bad
(M9-R1-D2). The check does no network access: no revocation lookup on Windows, no network validation on
macOS, so a user cannot be made to wait on, or be steered by, a certificate authority's server.

*Expired signatures.* A candidate PE whose signing certificate has expired (and carries no timestamp) is
`candidate_invalid`: a packaging mistake. An *installed* entry whose certificate has since expired is not
`installed_invalid`: its subject is read from the same trust state and serves as the baseline, and when
that is not available the outcome is `installed_unsigned`, so an install does not block its own updates
because its certificate aged (M9-R1-D3). Timestamping every signature (every example template in CLI.md
does) avoids the case. An installed tree whose files were changed locally after install fails with
`installed_invalid`, which `enforce` refuses without marking anything; the recovery is a reinstall. The
tree's integrity is not what this check establishes (the release-signed manifest did that when it was
staged); it only asks who published it.

*Policy and default.* The policy is the installed version's, never the candidate's, and no option lowers
it; an attacker who can edit the installed tree can already replace the runtime. The packager writes
`enforce` by default when the target's OS has a `[codesign.<os>]` section (M9-D6). Its cost is that a
publisher who changes certificate subject (a renewal under another organisation name, OV to EV) must first
ship one release with `warn` (CLI.md, "Moving to another publisher"), or users are stuck on the old
publisher's last release.

**Signer processes (M9-D3).** The developer's templates run as direct child processes: never through a
shell, a `.bat` or `.cmd` program refused on Windows, standard input closed, standard output and error
capped at 64 KiB each, the child killed and reaped after its timeout. Placeholders are whole arguments and
expand to absolute paths, so an expansion cannot be read as an option. `lunepack` prints the item's relative
path and, on failure, the template's key, the program's file name, the exit status (or "timed out") and
the last 4 KiB of standard error with every `{env:}` value of that call replaced by its name; it never
prints or logs the expanded arguments or any environment variable. `{env:NAME}` values are on the child's
command line, which other local users can read: they are for paths, key ids and identity names, never for a
secret value (docs say so). A signing tool inherits the packager's environment, so a credential reaches it
there or in a file the tool reads, and a tool that echoes it into its own standard error would show it in
this tail; use a tool and options that do not. The signing tool is the developer's own trusted code: a
malicious one signs what it wants; the stage only checks that the item really is in a signed form after the
call (a template that exits 0 and changes nothing, or signs another file, fails the pack).

**The staple ticket.** Stapling writes `Contents/CodeResources` into the bundle; the stage runs before
hashing, so the ticket is a file of the release, covered by the manifest, and a pack that holds no ticket
after `staple` fails. The ticket proves nothing about the release signature; it lets Gatekeeper accept the
app offline.

**Not proven by the gate or CI.** The real Developer ID path (the notary accepting lunepack's zip, hardened
runtime on the runtime and UI, stapling, translocation of a notarized app, Gatekeeper's verdicts) is shown
only by a person running `scripts/macos-sign-check.sh` with their own identity; CI proves the mechanics with
ad-hoc and throwaway self-signed identities. Windows install rows with real signatures run on CI runners.

## Windows per-machine (M10)

An app installed for all users lives in `Program Files`, where a standard user cannot write. To update it
with no prompt per update, the install registers one small Windows service per app, running as LocalSystem,
that any local user's copy of the app may start and talk to over a named pipe (FORMAT.md 18 and 19; D12,
M10-D1 to M10-D20). The service is therefore a local-privilege boundary: it is fed by every user of the
machine and holds the rights of the machine. This section says what it trusts, what a local user can and
cannot do through it, and what is not covered.

**What the service trusts.** Its own image path (from which it finds the install root), the files and the
machine record under `Program Files\<App>` (writable by administrators only; it checks the owner and every
entry of `R`, `R\app`, `R\.lunepack`, `R\.lunepack\state` and `R\.lunepack\machine` at the start of every
operation and refuses with `not_protected` when anyone else holds a write-class right), and the publisher's
root key and the floors in the machine record. It reads no environment variable and no current directory,
and takes no path, URL or app id from a caller.

**What it does not trust.** Anything a user sends. The client streams the signed documents and the update's
bytes; the service writes them into a folder only administrators can reach (`R\.lunepack\machine\incoming`),
hashes them as they are written, and verifies the whole chain there (root, key set, feed, manifest, every
file's hash) before it builds anything. It checks that the update is newer than what is installed, not marked
bad, for this app and this channel (the channel named in the installed tree's own signed configuration, never
one a caller names, M10-D18), and selects the candidate itself from the feed it verified, with the same core
functions the library uses, so there is no second parser to differ from the first. It never runs code from an
update before that update is verified, never downloads anything, and keeps no secret a user could read.

**The service never impersonates and opens no user file** (M10-D2). The client sends bytes; the service
never opens a path in a user's namespace and calls no impersonation API, so a file or library opened by
mistake cannot resolve through a caller's device map. The client connects at identification level (the
service can learn who the caller is and cannot act as it), and, before it sends a byte, checks that the pipe
is owned by LocalSystem, so a process that created the pipe name first cannot receive the update or answer
for the service.

**What a local user can do** through the service: trigger any update the publisher signed for this app and
channel that is newer than what is installed (anyone who can run the app can); report a version healthy or
broken while they are the one applying it (they hold its token); make the update fail, or roll it back, by
being the one who applies it and then exiting or crashing the app, the same power the user has over their own
install; deny service to other users by holding the pipe for the length of one connection (the service serves one
connection at a time, with 5 s, 30 s and 30 min deadlines), by holding the engine's lock during an operation,
or by being first to apply and then rolling back; and read the machine record, which is world-readable and
holds no secret (the token is stored only as its SHA-256). **What they cannot do**: install anything not
signed by the publisher's keys, install an older or a bad-marked version, write or read anything as
LocalSystem, confirm or roll back someone else's pending update during its health window (they lack the
token), change the service's configuration, the descriptors or the policy (an administrator's HKLM key), or
add a second instance of the pipe and receive its clients (no entry for a non-administrator holds the right
to create an instance; the first instance is created with the first-instance flag, and a name that exists
is an error). The token and the supervision lease keep **bystanders** out of someone else's health window;
they do not keep the user who applies a version from making it roll back or stick, and are not meant to.

**The pipe is untrusted input.** Frames and messages are length-prefixed and capped before any allocation;
a message is one strict JSON object with a closed member set; anything malformed ends the connection; the
codec is pure core code with a fuzz harness (`fuzz/fuzz_targets/service.rs`, seeds replayed by the gate) and
a golden file that pins the wire bytes (FORMAT.md 19.7). No message carries a path, an operating-system
error text, an install id, a token digest or key material. A flaw in this parser or in the staging code
reached through it would be a local privilege escalation, which is why the security review of M10 tests
parser differentials against the golden file.

**Root rotations.** The machine learns a root rotation only when an update is staged by the engine (its own
check verifies the chain from the machine's root forward). Until then the machine record keeps the older
root, and a user's check walks forward from it; a user's counters can never move the machine's root
(M4-SEC-obs1).

**The first install and the anchor.** `Setup.exe` sits in a folder the installing user can write, and the
elevated engine reads its payload after an administrator consented to a User Account Control prompt. The
setup file carries digests of its own payload in a resource of its runtime image (FORMAT.md 14.5); the
elevated copy reads them from its own mapped image, which the administrator consented to and a process
cannot change afterwards, copies the payload into an administrator-only folder and verifies it there, so a
payload swapped **after** the prompt fails the check before anything is written. It does not help against a
whole file swapped **before** the prompt: only an Authenticode signature (M9) lets the administrator tell a
genuine `Setup.exe` from a swapped one, because the prompt then names the publisher. **An unsigned
`Setup.exe` shows "Unknown publisher" at the prompt, for the genuine file and a swapped one alike.** Sign
the installer of an app that installs for all users.

**The elevated modes** (`machine-install`, `machine-repair`, `machine-uninstall`) run as an administrator
after consent, started by the same build's unelevated side. They read no environment variable, make no
temporary directory, look at no current directory, start no window and open no network connection, take no
path from their command line (only a progress-pipe id and the SID of the one account that may read it), and
derive the install root from their own image's path or from the setup file's own image. The hand-off pipe is
owned by Administrators, readable by that one account and outbound only: the elevated side reads nothing from
the unelevated one. The unelevated side decides success from the machine record and the exit code, never
from a line that came through the pipe. The UI never runs elevated (D35, M10-D15): the runtime starts no UI
from a process holding a UAC elevation's full token, and an uninstall started from such a process (or with UAC
off) skips the copy in the user's temporary directory, which that user's unelevated processes could replace,
and runs its first phase from the runtime under Program Files. The packaged binaries are
hardened against DLL planting as the runtime is (the loader searches System32 only), and the end-to-end suite
starts the service, its self-test and Setup's elevated mode beside files named like DLLs.

**Where the boundary is the platform's.** With UAC switched off, or when the administrator's account is the
built-in Administrator, an administrator's process holds the full token, so there is no elevation boundary
to defend between that user's processes and the machine: such a process can do what the service does. The
boundary this section describes is between standard users, and an administrator's own unelevated processes,
and the machine.

**The policy** (`HKLM\SOFTWARE\Policies\lunepack\<app id>`, FORMAT.md 18.4) is read only; only an
administrator can write it. An unreadable, mistyped or unknown value counts as "on", so a damaged policy
errs toward no update. A service an administrator disabled stops updates for standard users until `repair` or
re-enabling; that is an administrator's deliberate choice on that machine and not something a standard user
routes around (M10-D13).

**The removal guard on Windows** (M10-D20). Every deletion the engine makes under `R` (a version tree, a
leftover `.gc-` folder, a service folder, `R` itself at uninstall) is decided by one question asked twice: once before the
rename that takes the path away from new launches, once on the renamed path right before the deletion. On
Windows the answer is the process scan **or** a file-system probe that opens every file of the tree for
write and delete and every directory and reparse point for delete, all with full sharing and each closed at
once; an open that fails for any reason means "in use", and only a clean "not in use" lets the engine delete.
The probe sees what the rename does not (a running executable, a DLL loaded by any process, whether the scan could
inspect that process or not) and what the scan does not (a working directory, a held file). **A rename is not
an in-use check on Windows** (measured on Windows 11): a folder can be renamed while a program runs from an
executable inside it and while a process outside it has a DLL from it loaded; it fails only when a working
directory is inside or a file is held without delete sharing. So the engine's rename only keeps new
launches out; the probe is the guard. Known gaps, each failing toward leaving a folder: a file mapped as data
after its handle was closed is not seen (its deletion then fails and the folder stays, though files deleted
before that one are gone); a process that maps a tree file through a handle it opened with full sharing
before the rename, after the second check; and a file with the read-only attribute makes its tree count as in
use for good (lunepack never sets it). The per-user in-use scan of `Process::tree_in_use` on Windows still
skips a process it cannot open (a parked follow-up that this milestone does not change), so the per-machine guard, which does not depend on
opening other processes, is stricter than the per-user one; the two differ. A refused machine uninstall puts
back what it had done before the refusal and leaves the install as it was.

**What survives an uninstall.** Other users' per-user homes (`<LocalAppData>\lunepack\<app id>`, FORMAT.md
18.5: their counters, cache and logs) are left in place; the uninstalling user's home is removed. They hold
no secret and no root, and a later reinstall reads the counters again.

## Denial-of-service bounds

| Resource | Bound |
|---|---|
| Document bytes | 64 KiB root and key set, 8 MiB feed, 64 MiB manifest (and the feed's signed size) |
| Signature checks per document | at most 16 signatures, each a single Ed25519 verification |
| JSON | depth 32; duplicate keys rejected; integers at most 2^53 − 1 |
| Counts | 16 root keys, 64 release keys, 10,000 releases, 200,000 entries |
| Downloads | capped by signed sizes; nothing fetched is trusted before its hash matches. A response's `Content-Length`, when present, must equal the expected byte count and is checked before the body is read; a body is read to at most that count and fails on one byte more (M4-D9) |
| Range requests | one at a time; at most 64 runs, else the full pack; a `200` to a Range request becomes the full-pack download, never a second request (M4-D8) |
| Install-state records | at most 1 MiB each; at most three kept after a commit |
| Decoder memory | the signed dictionary per LZMA2 stream, at most 16 MiB (three for BCJ2), checked before allocation; concurrent decoders limited by a memory budget |
| Decoder output | exactly the signed size; decoding stops as soon as it would exceed it |
| Root walk | each step needs signatures from both roots, so its length is bounded by real rotations; a check also stops after 1024 steps |
| Freeze | feed and key-set expiry turn a silent freeze into a reported error |
| UI frames (M6) | a body of at most 1 MiB, checked before allocation; name and publisher at most 128 scalars, version at most 128, location at most 4096 bytes, at most 64 leftovers of at most 4096 bytes; an icon of at most 512 KiB of PNG, decoded within 1024 by 1024 pixels and 16 MiB; at most 64 frames waiting for the UI; one liveness probe out at a time |
| UI stalls (M6) | one write in progress at most 2 s; a hello within 20 s; an answer to a probe within 15 s; 5 s to exit after `Close`; then the engine kills its own child and goes on headless |
| Setup trailer (M6) | the last 4096 bytes of the file, parts within FORMAT.md 4's caps and the file's size; the runtime taken from the pack at most 256 MiB |

Memory budget (M4-D11, M4-D13). Staging charges each decode job `length + decoder memory + 256 KiB`
of I/O buffers against a budget (default 256 MiB) and runs at most `min(available_parallelism, 8)`
jobs at once. The decoder memory is the frame's signed dictionaries plus a constant per codec
measured for `lzma-rust2` (about 10 MiB for the LZMA2 variants, about 12 MiB for BCJ2, none for
stored), and a measurement test keeps the constants above what the decoder really allocates. A job
that alone exceeds the budget runs only when nothing else runs, so a large signed frame slows
staging and never deadlocks it. The peak is therefore bounded by the budget plus one oversized job,
and by the signed sizes, not by anything the host sends.

Cancel latency. Cancelling or dropping an operation stops its work at the next check: the transport
is polled on the caller's task, file I/O and decoding run on lunepack's worker threads and look at
the cancel token between chunks, jobs and writes. The default HTTP transport is the exception: a
worker blocked inside a socket read ends at the per-read timeout (30 s by default, a builder
option), and the updater lock stays held until that worker returns, so a new operation meanwhile gets
`Busy`. An injected async transport has no such delay, because its futures die with the operation's.
A host that stalls a connection can therefore delay a retry by up to the read timeout; it cannot
corrupt anything.

## Clock

Expiry and key windows use the local clock only. A clock set earlier than the installed release's
signed `issued` time is implausible: expiry and key-window checks are skipped and the skip is
reported, so a wrong clock cannot brick updates. The cost is that an attacker who can also set the
clock back (a local attacker, classes 4 and 5) defeats expiry; signatures, binding and floors still
hold.
