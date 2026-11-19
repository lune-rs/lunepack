# Threat model

Status: **draft**, awaiting approval together with `docs/FORMAT.md`.

What lunepack's update and install path defends against, and what it does not. The format rules
referred to here are in `docs/FORMAT.md`; the decisions in `docs/DECISIONS.md` (D7, D17, D21, D24,
D33, D34, D35, D36 to D41, M3-D1 to M3-D13, M4-D1 to M4-D23, M6-D1 to M6-D12, M7-D1 to M7-D22).

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
- Per-machine installs: the privileged engine takes only an app id and payload handles the caller
  opened itself, copies the payload into an admin-only staging directory, and only then verifies
  the whole chain (copy, then verify: no time-of-check/time-of-use window). It never follows a
  caller-supplied path or URL, never runs payload code before verification, and never acts for an
  app id without a protected install record. Machine-scope floors are kept by the engine; the
  non-elevated library also keeps its own floors and enforces the higher of the two.
- The library never writes the machine install's state (M4, FORMAT.md 12.6): it reads the machine
  record and the tree through the layout, and writes only this user's `install-counters` records,
  cache and lock in the user's own directories. Another user cannot lower this user's floors, and
  this user's counters cannot lower the machine record's: a check uses the field-wise higher of the
  two. A counters record whose install id differs from the machine record's stops the load.

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
protects nothing a local process could not do anyway. Per-machine installs, which arrive later,
always need it (C8).

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
  locator accepts unchanged; a real timestamp authority is not exercised before code signing (M9).
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
  flagged binary is code signing (M9), not an exclusion.
- **Renaming the install folder** is unsupported (`docs/FORMAT.md` 16): the launcher still works from the
  renamed folder, the shortcut no longer matches the install's marker and is left alone, and updates
  report it as a conflict. Nothing is overwritten or removed that is not lunepack's.

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
