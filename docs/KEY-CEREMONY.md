# Key ceremony: the signing keys of an app that updates itself

An app that updates itself trusts a small set of public keys, and nothing else, to say which files are
its next version. This guide is for the publisher of such an app: it makes the keys, says where each one
lives, and covers the moments when they change (a rotation, a revocation, a leak). It uses the
`lunepack` command line ([`CLI.md`](CLI.md)); the documents it produces are defined in
[`FORMAT.md`](FORMAT.md), and what each key is worth to an attacker is in
[`THREAT-MODEL.md`](THREAT-MODEL.md). If you have not packed a release yet, read
[`GETTING-STARTED.md`](GETTING-STARTED.md) first, or [`INTEGRATION.md`](INTEGRATION.md) for an app in
another language.

Nothing here adds a rule of its own. Where a rule matters, the guide links to the page that states it.

## How the blocks below were made

Every command block was run, in a scratch directory, with keys made at that moment, on a Linux machine;
the output under it is what the command printed. The keys are throwaway and are gone. Conventions:

- 64-character hex values (public keys, key ids) are shortened to `8 characters...4 characters`.
- Times, `seq` numbers and sizes are those of that session.
- `date -d` is GNU date; any way of writing a Unix time in seconds does the same.
- A block marked "(not run: ...)" was not run, and says why.

## 1. The two kinds of key

Every document a client reads is signed, and a client checks the chain from a root it already holds
([`FORMAT.md` section 11.1](FORMAT.md)):

| | Root keys | Release keys |
| --- | --- | --- |
| What they sign | `keys.json` (the list of release keys) and a rotation of the root (`root-<k>.json`) | the feeds (`feed-<channel>.json`) and the manifests |
| How many | 1 to 16, with a threshold: how many must sign | 1 to 64 in a key set, with a threshold |
| Where clients get them | compiled into the app's update configuration | from `keys.json`, which the root signed |
| How a client replaces them | a rotation signed by the old and the new root | a new `keys.json` signed by the root |

([`FORMAT.md` section 5](FORMAT.md) for the root, section 6 for the key set.) A key is an Ed25519 key; a
signer's private key never leaves the publisher, and only public keys reach a client. The *key id* is the
SHA-256 of the public key and appears in the tool's output.

The two kinds have different jobs. The root key is the one that can change who is trusted, so it
stays offline and is used rarely. The release key signs every release, so it lives where releases are
built. A leaked release key is recoverable without any change to the installed apps; a leaked root key is
the serious case (sections 7 and 8).

## 2. Decide before you start

- **How many root keys, and the threshold.** A threshold of `m` of `n` means any `m` of the `n` holders
  can sign, and fewer cannot ([`FORMAT.md` section 5.1](FORMAT.md): `1 <= threshold <= keys <= 16`). A
  threshold above 1 means one leaked key is not enough for an attacker
  ([`THREAT-MODEL.md`, "Leaked root key"](THREAT-MODEL.md)); the same number is how many holders must be
  reachable to sign a key set or a rotation, so a root whose holders can no longer reach the threshold
  cannot sign a new key set. This guide uses 2 of 3.
- **Release keys.** Each key in a key set has a window (`not_before`, `not_after`; a new key defaults to
  now until two years from now), and the key set may have an expiry. Short windows and an expiry bound
  what a leaked key can do and how long a withheld key set can freeze clients
  ([`THREAT-MODEL.md`, "Leaked release key"](THREAT-MODEL.md)).
- **Feed lifetime.** A feed expires 90 days after it is signed unless `--expires-after-days` says
  otherwise; past that a client sees "no update" and an error, so someone has to run `feed refresh`
  before then ([`CLI.md`, "`lunepack feed add`"](CLI.md)).
- **Where each key lives.** Keep root keys offline and out of CI; give CI only a release key with a short
  window ([`THREAT-MODEL.md`, "Packager and signing keys"](THREAT-MODEL.md)).

## 3. Make the root keys

Do this on a machine that is not connected to anything, one key per holder. `keys gen` writes the private
key file with mode 0600 and never over an existing file, and the directory must exist; on Windows the file
inherits the ACL of its directory, so put it in a directory only its holder can read
([`CLI.md`, "Key file format"](CLI.md)).

```
$ mkdir ceremony
cd ceremony
mkdir keys release
```

```
$ lunepack keys gen keys/root-1
public: 81e671cd...987e
id: 964ddfd1...18c2
wrote the private key to keys/root-1.key
```

The same command makes `keys/root-2` and `keys/root-3`, one for each holder. The first two lines are on
stdout, the last on stderr. Only public keys leave the offline machine: `init` takes them and writes the
configuration, which holds public keys and the places to find signers, never a key:

```
$ ROOT1=$(lunepack keys show --sign file:keys/root-1.key | sed -n 's/^public: //p')
ROOT2=$(lunepack keys show --sign file:keys/root-2.key | sed -n 's/^public: //p')
ROOT3=$(lunepack keys show --sign file:keys/root-3.key | sed -n 's/^public: //p')
lunepack init --app-id org.example.hello --threshold 2 \
    --root-key "$ROOT1" --root-key "$ROOT2" --root-key "$ROOT3"
wrote lunepack.toml
wrote lunepack-state.json
```

The three root keys and the threshold 2 are now in `lunepack.toml`. Every pack of an app with `[update]`
copies that root into the app's update configuration, which is how a client comes to trust it
([`CLI.md`, "Self-updating apps"](CLI.md)). `lunepack-state.json` is the publisher's memory of what it
last signed (section 9).

Name where each private key is, so that `--sign root-1` finds it. Add to `lunepack.toml` (a command
signer, `command = [...]` with the key's public hex, takes the place of a file for a key that must not
leave an HSM or a KMS: [`CLI.md`, "Command signer protocol"](CLI.md)):

```toml
[signers.root-1]
file = "keys/root-1.key"

[signers.root-2]
file = "keys/root-2.key"

[signers.root-3]
file = "keys/root-3.key"

[signers.release-a]
file = "keys/release-a.key"

[signers.release-b]
file = "keys/release-b.key"

[signers.ci]
env = "LUNEPACK_SIGNING_KEY"
```

## 4. Make the release keys

```
$ lunepack keys gen keys/release-a 2>/dev/null
lunepack keys gen keys/release-b 2>/dev/null
public: 11e20746...22f0
id: 2a262cb7...95c6
public: e8275903...240a
id: d970c653...822d
```

Two release keys, `a` for now and `b` for the replacement of section 7. A real publisher keeps only the
one it signs with on the build machine.

## 5. Sign the first key set

`keys set` writes `keys.json`: exactly the listed release keys, signed by the root. It needs as many
root signers as the root's threshold ([`CLI.md`, "`lunepack keys set`"](CLI.md)):

```
$ RELA=$(lunepack keys show --sign release-a | sed -n 's/^public: //p')
RELB=$(lunepack keys show --sign release-b | sed -n 's/^public: //p')
lunepack keys set --release-dir release --release-key "$RELA" --sign root-1
error: the root needs 2 signer(s), 1 given
```

With two holders:

```
$ lunepack keys set --release-dir release --release-key "$RELA" \
    --sign root-1 --sign root-3 --expires "$(date -d '+1 year' +%s)"
change: a first key set: 1 key(s), threshold 1
keys.json: version 1, root 1, 1 key(s), threshold 1
```

The release threshold defaults to 1 for a first key set; `--threshold` raises it. `--not-before` and
`--not-after` set a key's window; `--expires` sets the key set's expiry and is not carried over from the
previous key set, so give it again each time you want one (the next `keys set` below prints
`expires ... -> none`). Before it places anything `keys set` prints a `change:` line naming what changes,
by key id.

## 6. Day to day

The build machine holds one release key and no root key. It packs, signs the manifest and the feed with
it, and publishes:

```
$ mkdir input
echo "version one" > input/notes.txt
lunepack pack --input input --version 1.0.0 --target linux-x86_64 \
    --release-dir release --sign release-a
lunepack feed add --release-dir release --channel stable --version 1.0.0 --sign release-a
delta: base(s) none
assemble: copied input
code-sign: 0 item(s)
hash: 1 file(s), 0 dir(s), 0 symlink(s), 12 bytes
pack: 1 distinct file(s) encoded on 1 worker(s)
sign: manifest signed by 1 key(s)
verify: manifest, pack and 1 frame(s) ok
placed: release/1.0.0/linux-x86_64.pack
placed: release/1.0.0/linux-x86_64.manifest.json
totals: 1 file(s), 12 input bytes, 12 pack bytes
codec stored: 1
verify: 1.0.0/linux-x86_64.manifest.json and its pack ok (1 frame(s))
placed: feed-stable.json (seq 1795581584000, 1 release(s), 1 manifest(s) verified)
```

In CI the key does not sit in a file: a signer of the form `env = "LUNEPACK_SIGNING_KEY"` reads a PEM
key from that environment variable. The variable is visible to the process that holds it and to its
children, so set it on the one command that needs it ([`CLI.md`, "Signer specs"](CLI.md)). Section 7 does
this.

Keep `lunepack.toml` and `lunepack-state.json` together, in storage of your own, and never write from a
release directory you fetched from the public host: anyone who can write there can put an older document
back ([`CLI.md`, "The publisher state file"](CLI.md#the-publisher-state-file-m3-r2-d1)).

## 7. Replace a release key

The same steps serve a routine replacement and a leaked key. A removed key's feed cannot be repaired in
place, so it is done in two moves, and nothing is uploaded between them
([`CLI.md`, "Revoking a release key"](CLI.md#revoking-a-release-key)). The tool refuses the shortcut:

```
$ lunepack keys set --release-dir release --release-key "$RELB" --sign root-1 --sign root-2
error: `keys set` would leave documents that no longer verify under the new key set (nothing was written):
  feed-stable.json: does not verify: 0 of 1 required distinct keys verified
refresh the feed with a key you keep before removing this one; drop releases whose manifests only removed keys signed (`feed refresh --drop <version>`); or pass --allow-unverifiable-feeds to place it anyway
```

Move 1: list both keys, so the old feed still verifies:

```
$ lunepack keys set --release-dir release --release-key "$RELA" --release-key "$RELB" \
    --sign root-1 --sign root-2
change: version 1 -> 2: added d970c653...822d; expires 1827117584 -> none
keys.json: version 2, root 1, 2 key(s), threshold 1
```

Sign what you publish from now on with the new key. A release whose manifest only the old key signed
cannot be carried to a feed signed by the new key: re-pack it as a new version, or drop it
(`feed refresh --drop <version>`):

```
$ echo "version two" > input/notes.txt
lunepack pack --input input --version 1.1.0 --target linux-x86_64 \
    --release-dir release --sign release-b
lunepack feed add --release-dir release --channel stable --version 1.1.0 --sign release-b
lunepack feed refresh --release-dir release --channel stable --drop 1.0.0 --sign release-b
delta: base(s) 1.0.0
assemble: copied input
code-sign: 0 item(s)
hash: 1 file(s), 0 dir(s), 0 symlink(s), 12 bytes
pack: 1 distinct file(s) encoded on 1 worker(s)
delta: 1 base(s), 0 delta file(s)
sign: manifest signed by 1 key(s)
verify: manifest, pack and 1 frame(s) ok
placed: release/1.1.0/linux-x86_64.pack
placed: release/1.1.0/linux-x86_64.manifest.json
totals: 1 file(s), 12 input bytes, 12 pack bytes
codec stored: 1
no-patch: notes.txt from 1.0.0: not-smaller (patch 16 bytes, frame 12 bytes)
delta: from 1.0.0: no patch
verify: 1.0.0/linux-x86_64.manifest.json and its pack ok (1 frame(s))
verify: 1.1.0/linux-x86_64.manifest.json and its pack ok (1 frame(s))
placed: feed-stable.json (seq 1795581584001, 2 release(s), 2 manifest(s) verified)
verify: 1.1.0/linux-x86_64.manifest.json and its pack ok (1 frame(s))
placed: feed-stable.json (seq 1795581584002, 1 release(s), 1 manifest(s) verified)
```

Move 2: list only the new key.

```
$ lunepack keys set --release-dir release --release-key "$RELB" --sign root-1 --sign root-2
change: version 2 -> 3: removed 2a262cb7...95c6
keys.json: version 3, root 1, 1 key(s), threshold 1
```

```
$ lunepack verify release
root: version 1 ok
keys.json: version 3, 1 key(s), threshold 1 ok
feed-stable.json: seq 1795581584002, 1 release(s) ok
1.1.0/linux-x86_64.manifest.json: manifest and pack ok (1 frame(s) decoded)
1.0.0/linux-x86_64.manifest.json: unreferenced (no feed lists it)
verified: 1 feed(s), 1 manifest(s), 1 unreferenced
```

Then upload `keys.json` and the feeds, in the upload order of [`CLI.md`](CLI.md#the-release-directory). A client
that fetches the new `keys.json` rejects documents signed by the removed key, and the key-set floor stops
the old key set from coming back ([`FORMAT.md` section 11.2](FORMAT.md)); no app update is needed.

CI's signer is now the new key. The `ci` signer of the configuration reads it from the environment of
the one command that signs (the function `secret` here stands for whatever hands your CI its secret; in
the session it read the throwaway key file):

```
$ echo "version three" > input/notes.txt
LUNEPACK_SIGNING_KEY="$(secret)" lunepack pack --input input --version 1.2.0 \
    --target linux-x86_64 --release-dir release --sign ci
LUNEPACK_SIGNING_KEY="$(secret)" lunepack feed add --release-dir release --channel stable \
    --version 1.2.0 --sign ci
delta: base(s) 1.1.0
assemble: copied input
code-sign: 0 item(s)
hash: 1 file(s), 0 dir(s), 0 symlink(s), 14 bytes
pack: 1 distinct file(s) encoded on 1 worker(s)
delta: 1 base(s), 0 delta file(s)
sign: manifest signed by 1 key(s)
verify: manifest, pack and 1 frame(s) ok
placed: release/1.2.0/linux-x86_64.pack
placed: release/1.2.0/linux-x86_64.manifest.json
totals: 1 file(s), 14 input bytes, 14 pack bytes
codec stored: 1
no-patch: notes.txt from 1.1.0: not-smaller (patch 18 bytes, frame 14 bytes)
delta: from 1.1.0: no patch
verify: 1.1.0/linux-x86_64.manifest.json and its pack ok (1 frame(s))
verify: 1.2.0/linux-x86_64.manifest.json and its pack ok (1 frame(s))
placed: feed-stable.json (seq 1795581584003, 2 release(s), 2 manifest(s) verified)
```

### What a leaked release key costs

The attacker holds a key of the current key set. With a release threshold above 1 one key is not enough
([`THREAT-MODEL.md`, "Leaked release key"](THREAT-MODEL.md)). Until a client fetches the revoking key
set, the attacker can sign a feed and manifests and ship arbitrary code to clients they can serve, which
needs control of the hosting or the network. An attacker who also controls the hosting can withhold the
revoking key set; that freeze is bounded only by the key set's `expires` and the key's `not_after`, which
is why short windows and an expiry are worth setting. A release signed with the leaked key alone does not
also carry your OS code-signing identity, so an app packed with signing and `publisher_check = "enforce"`
refuses it as a second barrier ([`RUNTIME.md`, "Publisher continuity"](RUNTIME.md#publisher-continuity)).
It is not a substitute for revoking the key.

## 8. Rotate the root

`rotate-root` writes `root-<k+1>.json` signed by the current root and by the new root, and re-signs
`keys.json` under the new root, with the same keys and windows, one version higher. Both sides must
reach their own thresholds ([`CLI.md`, "`lunepack keys rotate-root`"](CLI.md)). A new root (three more
keys here, 2 of 3, as an example of moving to other holders):

```
$ lunepack keys gen keys/new-1 2>/dev/null
lunepack keys gen keys/new-2 2>/dev/null
lunepack keys gen keys/new-3 2>/dev/null
public: 13edbce1...0754
id: 19216972...3f8f
public: 8d866207...b275
id: 960b4294...cc91
public: c1dc17cb...caa6
id: 3d969b44...7651
```

```toml
[signers.new-1]
file = "keys/new-1.key"

[signers.new-2]
file = "keys/new-2.key"
```

```
$ N1=$(lunepack keys show --sign new-1 | sed -n 's/^public: //p')
N2=$(lunepack keys show --sign new-2 | sed -n 's/^public: //p')
N3=$(lunepack keys show --sign file:keys/new-3.key | sed -n 's/^public: //p')
lunepack keys rotate-root --release-dir release --new-threshold 2 \
    --new-root-key "$N1" --new-root-key "$N2" --new-root-key "$N3" \
    --sign root-1 --sign root-2 --sign-new new-1 --sign-new new-2
root-2.json written
keys.json re-signed under the new root
```

```
$ ls release
lunepack verify release
1.0.0
1.1.0
1.2.0
feed-stable.json
keys.json
root-2.json
root: version 2 ok
keys.json: version 4, 1 key(s), threshold 1 ok
feed-stable.json: seq 1795581584003, 2 release(s) ok
1.1.0/linux-x86_64.manifest.json: manifest and pack ok (1 frame(s) decoded)
1.2.0/linux-x86_64.manifest.json: manifest and pack ok (1 frame(s) decoded)
1.0.0/linux-x86_64.manifest.json: unreferenced (no feed lists it)
verified: 1 feed(s), 2 manifest(s), 1 unreferenced
```

Publish `root-2.json` before `keys.json`: clients walk the rotation from the root compiled into their
app, one `root-<k>.json` after another, and then check `keys.json` against the last root they accepted
([`FORMAT.md` section 5.2](FORMAT.md)). The config keeps the original root, and `verify` walks the same
way.

### What a leaked root key costs

The attacker holds root keys that meet the root threshold. They can sign a key set with release keys of
their own and a rotation to a root they control. A client that accepts such a rotation keeps the higher
root version, which then wins over the root compiled into the app, so an app update with a new compiled-in
root does not recover that client; only a reinstall does
([`THREAT-MODEL.md`, "Leaked root key"](THREAT-MODEL.md)). That is why the root stays offline, why a
threshold above 1 is worth its cost, and why a suspected leak is answered at once with a rotation you sign
first: a client that fetches your rotation before the attacker's has its floor raised to yours.

## 9. When `keys.json` goes missing

`lunepack-state.json` records the root version, the key-set version and the feed `seq` that this
publisher last signed or accepted, and every writer refuses to build on an older document than the
record ([`CLI.md`, "The publisher state file"](CLI.md#the-publisher-state-file-m3-r2-d1)). If `keys.json`
goes missing from the release directory, restore it from your own storage. `--allow-older-previous` will
build without it, but then `keys set` needs `--threshold` and the new key set starts at version 1, below the
key-set floor of every client that saw a later one, so those clients reject it.

## 10. A leaked key and the `seq` of a channel

A client keeps the highest feed `seq` it has seen, per channel ([`FORMAT.md` section 11.2](FORMAT.md)). A
leaked release key that meets the threshold can sign a feed with `seq` = 2^53-1; clients then keep that
floor, and the writer rule "`seq` strictly increases" stops `feed refresh` on that channel
([`CLI.md`, "Revoking a release key"](CLI.md#revoking-a-release-key)). The workaround is to publish under a
new channel name, which has its own `seq`:

```
$ lunepack feed add --release-dir release --channel stable-2 --version 1.2.0 --sign release-b
ls release
verify: 1.2.0/linux-x86_64.manifest.json and its pack ok (1 frame(s))
placed: feed-stable-2.json (seq 1795581584000, 1 release(s), 1 manifest(s) verified)
1.0.0
1.1.0
1.2.0
feed-stable-2.json
feed-stable.json
keys.json
root-2.json
```

(This shows only that a new channel starts its own feed; the poisoned feed was not simulated.) A client
reaches the new channel only when it is told the name: a pack's `[update] channel` sets it for
installs of that pack, and `check` and `download` take `--channel <name>`
([`RUNTIME.md`, "Command line"](RUNTIME.md#command-line)). Clients that are never told stay on the old
channel, so decide the new name and how your apps learn it before you need it.

## A checklist

- Root keys: made offline, one per holder, a threshold above 1, and copied nowhere else. Only the public
  keys went into `lunepack init`.
- The build machine and CI hold a release key only, with a window (`--not-after`) and a key-set expiry
  (`--expires`, given at every `keys set`).
- `lunepack.toml` and `lunepack-state.json` are kept together and backed up; the release directory is
  never fetched from the public host as the base for writing.
- A feed is refreshed (`feed refresh`) before its expiry.
- To replace or revoke a release key: two moves, with a feed signed by the key you keep in between.
- To change root holders: `keys rotate-root`, and `root-<k>.json` uploaded before `keys.json`.
- You have decided the name of the channel you would move to if a feed's `seq` is ever poisoned.
