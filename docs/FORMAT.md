# lunepack format v1

Status: **approved (format v1); frozen from the first published release.** Until a release is published
a rule may still be corrected; from then on, a change to any MUST or MUST NOT below is a format revision,
which the project records in its internal decision log.

This document is normative. The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
"Writer" means the lunepack packager (the only producer of these documents). "Reader" means any
lunepack verifier: the in-app library, the runtime, the privileged engine and `lunepack verify`.
All readers run the same core code, so every rule below holds for all of them alike.

A reader that meets anything this document does not allow MUST reject the whole document (fail
closed). There is no "best effort" mode and no warning-only path.

Decisions behind the format: D6, D7, D8, D21, D24, D25 and D33 of the project's internal decision log, which
is not part of this repository (each rule they settled is stated in this document). The threat model
is `docs/THREAT-MODEL.md`.

## 1. Artifacts and names

A release directory on any static host holds:

| Name | Kind | Signed by |
|---|---|---|
| `root-<k>.json` | `root`: root version `k` (k ≥ 2), one per root rotation | root `k-1`'s threshold and root `k`'s threshold |
| `keys.json` | `keys`: the key set | the current root's threshold |
| `feed-<channel>.json` | `feed`: one per channel, listing every target | the key set's release threshold |
| `<ver>/<target>.manifest.json` | `manifest`: one per release and target | the key set's release threshold |
| `<ver>/<target>.pack` | pack: the release's file frames (section 9) | not signed itself; bound by size and SHA-256 in the manifest |
| `<ver>/<target>.from-<old>.delta` | delta file: the patches from release `<old>` to this one (section 9.3), zero or more per release and target | not signed itself; bound by size and SHA-256 in the manifest's `deltas` |

- `<k>` is the root version in decimal without leading zeros. `<channel>` is a channel id
  (section 10.5). `<ver>` is the release's version string exactly as in the feed (section 10.3).
  `<target>` is a target id (section 10.4).
- `<old>` in a delta file's name is the base release's version string exactly as in the
  manifest's `deltas[].from` (section 9.3).
- Installers (`.exe`, `.dmg`, `.zip`, `.pkg`, `.tar.xz`, Linux `-setup`) are not part of the format;
  they carry the documents above unchanged.
- The writer MUST use exactly these names. Readers resolve the references inside documents
  (section 7.1) and MUST NOT rely on the names otherwise.
- Every `.json` artifact is a DSSE envelope (section 2) whose payload is one document (sections 3 and 5–8).
- A fifth kind, `prebuilt`, is not part of an app's release: `prebuilt-<version>.sig.json` is
  lunepack's own signed list of the prebuilt binaries of one lunepack release (section 21). No app
  reader opens it.

## 2. Envelope

Every document is a DSSE envelope serialised as JSON (DSSE protocol, JSON envelope).

### 2.1 Fields

The envelope is a JSON object with exactly these fields; any other field, at the envelope level or
inside a signature object, MUST be rejected:

| Field | Type | Rule |
|---|---|---|
| `payloadType` | string | exactly the type for the expected kind (2.2); compared byte for byte |
| `payload` | string | base64 (2.4) of the payload bytes |
| `signatures` | array | 1 to 16 signature objects |
| `signatures[].keyid` | string | REQUIRED (DSSE makes it optional); key id per 2.5 |
| `signatures[].sig` | string | base64 (2.4) of exactly 64 bytes (an Ed25519 signature) |

```json envelope
{
  "payloadType": "application/vnd.lunepack.keys.v1+json",
  "payload": "eyJmb3JtYXQiOjEsImtpbmQiOiJrZXlzIiwiY3JpdGljYWwiOltdfQ==",
  "signatures": [
    {
      "keyid": "69dff77e295327f8b3c2430b425e986b7020b92d03ec82b294ca6ed66cc4f72f",
      "sig": "p5GpjI7pdQDtYgJ4JCC3maaqprRBvxdbJxL19ybFeA1ePfUXHfwue7y7CAFp3VGHwqbdzbE08tVy/2WNLzoCJQ=="
    }
  ]
}
```

(The payload above is truncated to its common fields and the signature is a placeholder; the
example shows the shape only.)

### 2.2 Payload types

`payloadType` is `application/vnd.lunepack.<kind>.v1+json` with `<kind>` one of `root`, `keys`,
`feed`, `manifest`, `prebuilt`. The reader knows which kind it is opening and MUST reject any other type,
including a different case, extra whitespace or another version. The `v1` in the type and
`"format": 1` in the payload name the same format version.

### 2.3 Pre-authentication encoding (PAE)

Signatures are over `PAE(payloadType, payload)`, where `payload` is the decoded payload bytes (not
the base64 text, and not a re-serialisation):

```
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
```

`SP` is one space (0x20), `LEN(x)` is the byte length of `x` in ASCII decimal without leading
zeros, and `type` is encoded as UTF-8. Examples:

- `PAE("t", "x")` = `DSSEv1 1 t 1 x`
- `PAE("t", "")` = `DSSEv1 1 t 0 ` (ends with one space)
- `PAE("application/vnd.lunepack.keys.v1+json", "{}")` =
  `DSSEv1 37 application/vnd.lunepack.keys.v1+json 2 {}`

### 2.4 Base64

`payload` and `sig` use the standard base64 alphabet of RFC 4648 section 4 with `=` padding, in
canonical form only: the length is a multiple of 4, padding is present exactly when needed,
unused trailing bits are zero, and there is no whitespace or line break. URL-safe characters
(`-`, `_`) MUST be rejected.

This deliberately narrows DSSE, which says verifiers must accept both alphabets: each byte string
has exactly one accepted encoding, and lunepack's own writer is the only producer.

### 2.5 Keys, key ids and signatures

- The only signature algorithm in v1 is Ed25519 (RFC 8032), algorithm id `"ed25519"`. Any other
  `alg` value in a key list MUST be rejected.
- A public key is 32 bytes, written as 64 lowercase hex characters. It MUST be a canonical point
  encoding (decoding and re-encoding gives the same 32 bytes) and MUST NOT be a small-order point.
- A key id is the SHA-256 of the 32 raw public-key bytes, as 64 lowercase hex characters.
  Documents carry both the id and the public key; readers MUST recompute the id and reject a
  mismatch.
- A key list (in a root or a key set) MUST NOT contain the same public key twice, under any id.
- A signature is verified with strict Ed25519 verification: 64 bytes, `S` reduced (`S < L`), and
  small-order `R` or `A` rejected (`verify_strict` semantics).
- The envelope `keyid` only selects the key to try; it is an unauthenticated hint:
  - a `keyid` that is not 64 lowercase hex characters MUST fail the envelope;
  - a well-formed `keyid` not in the signing key list is skipped (it neither counts nor fails);
  - a signature that does not verify under the selected key is skipped;
  - the threshold counts distinct keys whose signature verified; two signatures by one key count
    once.

### 2.6 Opening an envelope

A reader opens an envelope in exactly this order and parses no payload field before step 7:

1. The document's byte length is at most the kind's size cap (section 4). Larger: reject before
   reading further.
2. Strict JSON check of the whole envelope (section 3.1).
3. Envelope fields per 2.1 (unknown fields rejected).
4. `payloadType` equals the expected kind's type (2.2).
5. 1 to 16 signatures; `payload` and every `sig` decode per 2.4; every `keyid` is well formed.
6. Each signature is verified over `PAE(payloadType, payload bytes)` per 2.5; the number of
   distinct verified keys is at least the threshold. Below threshold: reject.
7. Only now the payload bytes are parsed: strict JSON check (3.1), then the kind's fields.

## 3. Common payload rules

### 3.1 Strict JSON

Every envelope and every payload MUST pass these checks over the exact bytes that are then parsed:

- UTF-8 (RFC 8259) without a byte-order mark; invalid UTF-8 MUST be rejected.
- One JSON value whose top level is an object, followed only by JSON whitespace.
- No object, at any depth, has two members with the same name (after unescaping). This includes
  names the reader does not know.
- Nesting depth at most 32 (the top-level object is depth 1; each nested object or array adds 1).
- No escaped lone surrogate (`\ud800` without its pair, or the reverse).
- Integers are JSON numbers without sign, fraction or exponent, in `0 ..= 2^53 − 1`
  (9007199254740991). `-1`, `1.0`, `1e3` and `9007199254740992` MUST be rejected wherever an integer
  is expected. v1 has no non-integer numbers.
- Booleans are `true` or `false`; `null` is not a valid value for any v1 field (an optional field
  is written by omitting it).

### 3.2 Common fields

Every payload has:

| Field | Type | Rule |
|---|---|---|
| `format` | integer | MUST be `1` |
| `kind` | string | MUST equal the kind of the payload type (`root`, `keys`, `feed`, `manifest`, `prebuilt`) |
| `critical` | array of strings | REQUIRED, may be empty; at most 16 entries, each 1–64 bytes of `[a-z0-9-]`, no duplicates |

- **Critical features.** `critical` names features the payload uses that change its meaning. A
  reader MUST reject the document if any entry is not a feature it implements. v1 defines no
  critical features, so a v1 reader accepts only `"critical": []`.
- **Unknown fields.** Payload fields this document does not define are ignored (after the
  duplicate-key check). A future revision adds a field that old readers may ignore as a plain new
  field, and a field that changes meaning together with a `critical` entry.
- **Times** are integers: Unix seconds (UTC, leap seconds ignored).
- **Digests** (`sha256`) are 64 lowercase hex characters. Uppercase hex MUST be rejected.

## 4. Size and count caps

Readers MUST enforce these caps before the work they bound:

| Item | Cap |
|---|---|
| `root-<k>.json` document bytes | 64 KiB (65,536) |
| `keys.json` document bytes | 64 KiB |
| `feed-<channel>.json` document bytes | 8 MiB (8,388,608) |
| `<ver>/<target>.manifest.json` document bytes | 64 MiB (67,108,864) |
| `prebuilt-<version>.sig.json` document bytes, and its payload kept as a separate file (section 21) | 64 KiB |
| signatures per envelope | 16 |
| keys in a root | 16 |
| release keys in a key set | 64 |
| releases in a feed | 10,000 |
| entries in a manifest | 200,000 |
| LZMA2 dictionary per stream | 16 MiB |
| deltas in a manifest | 16 |
| patches in a delta | 200,000 |
| LZMA2 window of a patch (base and file together, section 9.3) | 128 MiB (134,217,728) |
| JSON nesting depth | 32 |
| rows in a prebuilt list (section 21) | 64 |

A manifest is additionally capped by the size its feed entry signs (section 7.1), which a reader
checks before downloading more bytes.

## 5. Root

### 5.1 Root payload

```json root
{
  "format": 1,
  "kind": "root",
  "critical": [],
  "app_id": "org.example.hello",
  "version": 2,
  "threshold": 1,
  "keys": [
    {
      "id": "69dff77e295327f8b3c2430b425e986b7020b92d03ec82b294ca6ed66cc4f72f",
      "alg": "ed25519",
      "public": "1754e7aaaa6f5bf4314eafabe40324b24bf80a06f81d82adbc0936dc027431a4"
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | app id (10.6) |
| `version` | integer ≥ 1 |
| `threshold` | integer, `1 ≤ threshold ≤ len(keys) ≤ 16` |
| `keys` | key objects `{id, alg, public}` per 2.5 |

### 5.2 Trusted root and rotation walk

- The app embeds a trusted root (its `app_id`, `version`, `threshold` and `keys`) at build time.
  A reader that has verified a higher root version before (persisted state) starts from that one
  instead: the higher version wins.
- Root version `k ≥ 2` is published as `root-<k>.json`. To rotate from trusted version `t`, the
  reader fetches `root-<t+1>.json` and accepts it only if all hold:
  1. the envelope opens (2.6) with root `t`'s keys and threshold;
  2. the same envelope also meets root `t+1`'s own threshold with root `t+1`'s own keys (the new
     root proves possession of its keys);
  3. `version` is exactly `t + 1` (no skipped versions);
  4. `app_id` equals the trusted root's;
  5. every key id is recomputed (2.5), no public key repeats, and the threshold is in range (5.1).
- The reader repeats with `t + 2`, `t + 3`, … until a `root-<k>.json` is absent, then checks
  `keys.json` against the last accepted root. Rotations are separate documents because a signature
  is checked before its payload is parsed: the key that signs a document cannot be learned from
  inside that document.
- A fetched root document that fails any check is an error, not "absent": the walk stops and the
  update check fails.
- The writer publishes `root-<k>.json` before a `keys.json` that names root version `k`.

## 6. Key set (`keys.json`)

```json keys
{
  "format": 1,
  "kind": "keys",
  "critical": [],
  "app_id": "org.example.hello",
  "root_version": 2,
  "version": 7,
  "expires": 1825027200,
  "threshold": 1,
  "keys": [
    {
      "id": "4e370fe519dde8336e0b4de9a949d6ef4108fd3aca913b6851cfd07ec77788aa",
      "alg": "ed25519",
      "public": "3e390113f06d1d397946537e7390f83a12d0738a67e9e4628dfb91040c1ecca5",
      "not_before": 1793491200,
      "not_after": 1888185600
    },
    {
      "id": "4238f924484cab5ac63b80b5320e731ee83d16771422b03efd4a1c737111e3ed",
      "alg": "ed25519",
      "public": "656b657b2e90cf78c88b90f16c9e51640dff79f6d1afa8ad5a96f370ce067491",
      "not_before": 1793491200,
      "not_after": 1888185600
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | equals the trusted root's `app_id` |
| `root_version` | equals the trusted root's `version` after the walk (5.2) |
| `version` | integer ≥ 1; at least the reader's key-set floor (11.2); equal is allowed |
| `expires` | OPTIONAL time; when present, the key set is expired at `now ≥ expires` (11.3) |
| `threshold` | release threshold: integer, `1 ≤ threshold ≤ len(keys) ≤ 64` |
| `keys` | release keys `{id, alg, public, not_before, not_after}`: key rules per 2.5, `not_before < not_after` |

- The envelope is signed by the trusted root's threshold (2.6).
- A release key is *valid at time `now`* when `not_before ≤ now < not_after`.
- Revocation: the root signs a new key set (higher `version`) without the key. Readers that have
  seen the new key set never accept the old one again (11.2).

## 7. Feed (`feed-<channel>.json`)

```json feed
{
  "format": 1,
  "kind": "feed",
  "critical": [],
  "app_id": "org.example.hello",
  "channel": "stable",
  "seq": 42,
  "issued": 1794528000,
  "expires": 1802304000,
  "releases": [
    {
      "version": "1.2.0",
      "targets": {
        "linux-x86_64": {
          "path": "1.2.0/linux-x86_64.manifest.json",
          "size": 2481,
          "sha256": "1c18f178331f99666543847f636694bb40b68c5d2b409c573415962787aaded9"
        },
        "macos-universal": {
          "path": "1.2.0/macos-universal.manifest.json",
          "size": 2730,
          "sha256": "3f7d4c792a20acd292bf2cc41556532f69e3ef5b94113f6d01775f1ae4511539"
        }
      },
      "rollout": {
        "basis_points": 2500,
        "seed": "44abc528db54f66d40174cfcdd43bab36285a5d953cbd185c672350a46f89691"
      }
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | equals the key set's `app_id` and the app id the reader expects |
| `channel` | channel id (10.5); equals the channel the reader asked for |
| `seq` | integer; at least the reader's floor for this channel (11.2); equal is allowed. The writer makes it strictly increasing per channel |
| `issued` | time the feed was written |
| `expires` | OPTIONAL time, `> issued`; the writer sets `issued + 90 days` (7,776,000 s) unless configured otherwise; expired at `now ≥ expires` (11.3) |
| `releases` | 0 to 10,000 release objects |
| `releases[].version` | version (10.3); no two releases in one feed have equal precedence (so two versions differing only in build metadata MUST be rejected) |
| `releases[].targets` | object, at least one member; each name is a target id (10.4), each value an artifact reference to that target's manifest |
| `releases[].rollout` | OPTIONAL; absent means everyone (10,000 basis points) |
| `rollout.basis_points` | integer `0 ..= 10000` (10000 = 100%) |
| `rollout.seed` | 32 bytes as 64 lowercase hex characters |

- The envelope is signed by the key set's release threshold, counting only keys valid at `now`
  (6; with the implausible-clock exception of 11.3).

### 7.1 Artifact references

An artifact reference is `{path, size, sha256}`:

- `path` is a relative reference to the artifact, resolved against the directory of the feed's own
  URL. It MUST pass the path rules of 10.1 and additionally use only ASCII `[A-Za-z0-9._+-]` in each
  component: so no scheme, query, fragment, percent sign or absolute form.
- `size` is the exact byte length and `sha256` the SHA-256 of the artifact's bytes. A reader MUST NOT
  read more than `size` bytes and MUST check both before using the artifact.

## 8. Manifest (`<ver>/<target>.manifest.json`)

```json manifest
{
  "format": 1,
  "kind": "manifest",
  "critical": [],
  "app_id": "org.example.hello",
  "version": "1.2.0",
  "target": "linux-x86_64",
  "issued": 1794528000,
  "pack": {
    "path": "1.2.0/linux-x86_64.pack",
    "size": 1113545,
    "sha256": "ee4f0443cd3cd07d4fb26e13101c3f4257ef94abe4ac6a6dc25d27decabc5577"
  },
  "entries": [
    {
      "path": "bin/hello",
      "type": "file",
      "size": 1048576,
      "sha256": "be4e2e81df0547f05c5ccf12af57ec1701c7f8465e1b542f6e1456b9d3f0876b",
      "exec": true,
      "frame": {
        "codec": "bcj-x86+lzma2",
        "offset": 0,
        "length": 412345,
        "sha256": "20333f298a01c85745b918b210674a2fbf82f0202474a7128fa12d0775f98262",
        "dict_size": 1048576
      }
    },
    {
      "path": "lib/libhello.so",
      "type": "symlink",
      "target": "libhello.so.1"
    },
    {
      "path": "lib/libhello.so.1",
      "type": "file",
      "size": 2000000,
      "sha256": "2460bf64dbd4b3339bb7f41c9fc8e20889a215e9ce1cf50ac76a7545fd0699e9",
      "exec": false,
      "frame": {
        "codec": "bcj2",
        "offset": 412345,
        "length": 700000,
        "sha256": "1bb5629b57e82f048ff63a42fd85dcd714fe5fd7b1861706a10c3e487b93461c",
        "streams": [
          { "length": 600000, "decoded_size": 1700000, "dict_size": 2097152 },
          { "length": 50000, "decoded_size": 200000, "dict_size": 262144 },
          { "length": 20000, "decoded_size": 100000, "dict_size": 65536 },
          { "length": 30000, "decoded_size": 30000 }
        ]
      }
    },
    {
      "path": "share/doc",
      "type": "dir"
    },
    {
      "path": "share/doc/README.txt",
      "type": "file",
      "size": 1200,
      "sha256": "f2f2e0c0de5d188f79d8aae7ac74f83fee226483f3d96924a2cea71b4c849987",
      "exec": false,
      "frame": {
        "codec": "stored",
        "offset": 1112345,
        "length": 1200,
        "sha256": "f2f2e0c0de5d188f79d8aae7ac74f83fee226483f3d96924a2cea71b4c849987"
      }
    },
    {
      "path": "share/doc/empty.txt",
      "type": "file",
      "size": 0,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "exec": false
    }
  ],
  "deltas": [
    {
      "from": "1.1.0",
      "path": "1.2.0/linux-x86_64.from-1.1.0.delta",
      "size": 196608,
      "sha256": "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a",
      "patches": [
        {
          "path": "bin/hello",
          "base_size": 1040384,
          "base_sha256": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
          "codec": "bcj-x86+lzma2",
          "offset": 0,
          "length": 131072,
          "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
        },
        {
          "path": "lib/libhello.so.1",
          "base_size": 1998848,
          "base_sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
          "codec": "lzma2",
          "offset": 131072,
          "length": 65536,
          "sha256": "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683"
        }
      ]
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | equals the feed's `app_id` |
| `version` | byte-equal to the feed release's `version` it was reached from (so also equal precedence) |
| `target` | equals the target id under which the feed listed this manifest |
| `issued` | time the manifest was written |
| `pack` | artifact reference (7.1) to the release's pack; `size` may be 0 when no entry has a frame |
| `entries` | 0 to 200,000 entries (8.1); the set passes the tree rules (10.2) |
| `install` | reserved: defined by a later revision, for install metadata a client needs before it downloads (such as a minimum OS). The entry point, name and icon are in the tree's update configuration (section 13), which the manifest covers by its file hash. v1 writers MUST NOT write it, and v1 readers reject a manifest that carries it |
| `deltas` | optional: 1 to 16 deltas (9.3), each the patches from one earlier release. Absent when the release has none; a writer never writes an empty list. Not a critical feature: a reader that uses no delta still installs the release correctly from the pack |

- The reader checks the manifest's byte length and SHA-256 against the feed's artifact reference
  **before** opening the envelope; then the envelope is signed by the key set's release threshold.
  Key validity windows are not checked for manifests: the feed, whose keys are window-checked,
  binds the manifest by hash.
- The writer lists entries sorted by `path` (byte order); readers do not depend on the order. Parent directories of an entry are implied;
  a `dir` entry is required only for an empty directory and allowed for any directory.

### 8.1 Entries

Every entry has `path` (10.1) and `type`, one of:

| `type` | Fields | Rules |
|---|---|---|
| `file` | `size`, `sha256`, `exec`, `frame` | `size` integer; `sha256` of the file's bytes; `exec` boolean, REQUIRED; `frame` present if and only if `size > 0` (a 0-byte file has no frame and `sha256` = SHA-256 of nothing) |
| `dir` | none | |
| `symlink` | `target` | only when the manifest's target is a `macos-*` or `linux-*` id; `target` per 10.2 |

There are no other mode bits: no permissions beyond `exec`, no owner, no timestamps, no extended
attributes. Readers create files non-executable unless `exec` is `true`, with the platform's
default permissions otherwise.

## 9. Frames and codecs

### 9.0 Frame descriptor

A file's `frame` describes one frame: a byte range of the pack holding the file's encoded bytes.

| Field | Rule |
|---|---|
| `codec` | one of the codec ids below, compared byte for byte |
| `offset` | integer; `offset + length ≤ pack.size` (computed without overflow) |
| `length` | integer ≥ 1 |
| `sha256` | SHA-256 of the frame's bytes `pack[offset .. offset + length]` |
| `dict_size` | the LZMA2 variants only (below) |
| `streams` | `bcj2` only (below) |

The codec-id set of v1 is closed:

| Codec id | Encoding | Extra fields |
|---|---|---|
| `stored` | the file's bytes unchanged | none; `length == size` and the frame's `sha256` equals the file's `sha256` |
| `lzma2` | one raw LZMA2 stream (no `.xz`, `.lzma` or `.7z` container) | `dict_size` |
| `bcj-x86+lzma2` | the x86 BCJ filter (start offset 0) applied before encoding, then one raw LZMA2 stream | `dict_size` |
| `bcj-arm64+lzma2` | the ARM64 BCJ filter (start offset 0) applied before encoding, then one raw LZMA2 stream | `dict_size` |
| `bcj2` | the BCJ2 x86 filter's four streams, concatenated (below) | `streams` |

- An unknown codec id, including a known id in another case, MUST fail the manifest (fail closed).
- `dict_size` is a power of two in `4096 ..= 16777216` (4 KiB to 16 MiB). Readers check it before
  allocating any decoder state; the decoder never uses a larger dictionary than the signed value.
- A field that belongs to another codec (a `dict_size` on `stored` or `bcj2`, `streams` on an LZMA2
  variant) MUST be rejected.

### 9.1 BCJ2 frames

A `bcj2` frame is exactly four sub-streams, concatenated in this order with no gap or padding:
MAIN, CALL, JUMP, RC. `streams` is an array of exactly four objects in that order:

| Stream | Encoding | Fields |
|---|---|---|
| MAIN | raw LZMA2 | `length`, `decoded_size`, `dict_size` |
| CALL | raw LZMA2 | `length`, `decoded_size`, `dict_size` |
| JUMP | raw LZMA2 | `length`, `decoded_size`, `dict_size` |
| RC | stored | `length`, `decoded_size` with `length == decoded_size`; no `dict_size` |

- Sub-stream `k` occupies frame bytes from the sum of the earlier lengths to that sum plus its own
  `length`. The four lengths MUST sum exactly to the frame's `length` (computed without overflow).
- Every `length` is ≥ 1. MAIN, CALL and JUMP `decoded_size` are each at most the file's `size`.
- `dict_size` per 9.0 for MAIN, CALL and JUMP.
- BCJ2 sub-streams carry no integrity check of their own: a changed byte decodes silently to
  different output. The frame hash (checked before decoding) and the file hash (checked after) are
  the only integrity checks, and both are required.

### 9.2 Decoding rules

A reader decoding a frame MUST, in this order:

1. read exactly `length` bytes of the frame (a different count is an error);
2. check the frame's SHA-256 against the signed `sha256` before any decoder sees a byte;
3. check the descriptor (9.0, 9.1) and allocate decoder state only within the signed `dict_size`s;
4. decode so that the output is exactly the file's `size` bytes: stop with an error as soon as the
   output would exceed `size`, and reject a short output;
5. require that every stream is consumed exactly: no trailing input after the end of an LZMA2
   stream, and each BCJ2 sub-stream decodes to exactly its `decoded_size`;
6. check the SHA-256 of the output against the file's `sha256` before the file is placed.

On any error the decoded output is discarded and never placed.

Frames may overlap or repeat inside the pack (identical files may share one frame): each frame is
hash-checked on its own. Pack bytes that no frame covers are allowed. The pack's own `sha256`
covers a full-pack download.

Decoder memory per frame is bounded by the signed dictionary sizes: one dictionary for the LZMA2
variants, the sum of three for `bcj2`, plus a small fixed overhead.

### 9.3 Delta files and patches

A delta lets a client that has release `from` installed rebuild a changed file from its own copy of
that file (the base) and a patch, instead of downloading the file's frame. Each element of the
manifest's `deltas` describes one delta file:

| Field | Rule |
|---|---|
| `from` | the base release's version string (10.3); its precedence MUST be strictly below the manifest's `version`, and no two deltas of a manifest may have `from` of equal precedence |
| `path`, `size`, `sha256` | artifact reference (7.1) to the delta file, `size ≥ 1` |
| `patches` | 1 to 200,000 patches |

Each patch:

| Field | Rule |
|---|---|
| `path` | names a `file` entry of this manifest with `size ≥ 1`; at most one patch per path in a delta |
| `base_size` | integer ≥ 1: the base file's size |
| `base_sha256` | SHA-256 of the base file's bytes; MUST differ from the entry's `sha256` |
| `codec` | `lzma2`, `bcj-x86+lzma2` or `bcj-arm64+lzma2`, compared byte for byte (`stored` and `bcj2` MUST be rejected; an unknown id fails the manifest as in 9.0) |
| `offset`, `length` | `length ≥ 1` and `offset + length ≤` the delta file's `size` (computed without overflow): the patch is the delta file's bytes `offset .. offset + length` |
| `sha256` | SHA-256 of the patch's bytes |

- **Codec meaning.** A patch is one raw LZMA2 stream whose preset dictionary is the base: the
  decoder starts with the base's bytes already in its dictionary, and the stream's first chunk does
  not reset it. For the BCJ ids, the base is passed through the same BCJ filter (start offset 0)
  before it becomes the dictionary, and the decoded output through the inverse filter, as for a
  frame of that id. There is no `dict_size` field.
- **Window.** The LZMA2 window of a patch is `base_size` plus the entry's `size`, rounded up to a
  multiple of 4096. It MUST be at most 134,217,728 (128 MiB); a reader checks it from the signed
  sizes before allocating anything, and never truncates the base to fit. Files of about 64 MiB
  and larger therefore have no patch and are fetched as frames.
- Patches may overlap or repeat inside a delta file, and bytes no patch covers are allowed. Every
  rule of this section fails the whole manifest, like any other field rule.
- Unknown members of a delta or patch object are ignored (3.2); duplicate keys are rejected (3.1).

**Choosing a delta.** A client uses only the delta whose `from` is byte-equal to the version
string of its installed release (precedence is not enough: two versions may differ only in build
metadata), and for a file only the patch whose `base_size` and `base_sha256` equal its installed
file at that path. Anything else is fetched as before (the file's frame, or the pack); a patch that
fails any check below is discarded and the file is fetched from its frame. Patches are an
optimisation: they never change which bytes are installed.

**Decoding rules.** A reader rebuilding a file from a patch MUST, in this order:

1. read exactly `length` bytes of the patch (a different count is an error);
2. check the patch's SHA-256 against the signed `sha256` before any decoder sees a byte;
3. check that the base file has exactly `base_size` bytes and that their SHA-256 equals
   `base_sha256`, before the base is used;
4. allocate decoder state only within the memory bound below (at most two windows plus the codec's
   fixed overhead);
5. decode so that the output is exactly the entry's `size` bytes: stop with an error as soon as the
   output would exceed `size`, and reject a short output;
6. require that the LZMA2 stream is consumed exactly: no trailing input after its end;
7. check the SHA-256 of the output against the entry's `sha256` before the file is placed.

On any error the decoded output is discarded and never placed. Decoder memory per patch is bounded
by at most two windows plus the codec's fixed overhead: a decoder may hold the window twice while
it grows it. The base (and its filtered copy for the BCJ ids) and the patch's bytes are the
caller's and are charged apart.

**Writer.** A writer writes one delta file per delta, named `<ver>/<target>.from-<from>.delta` with
`<from>` the delta's `from` text; its patches in the manifest's entry order, back to back from
offset 0 with no padding; and the deltas sorted by `from` precedence, highest first. A delta with no
patch is not written or listed, and a manifest without deltas has no `deltas` field. Which files
get a patch is the writer's choice and not a format rule: a writer may leave out any patch, for
instance one that is not smaller than the file's frame, or one whose encoder would not fit the
writer's memory budget.

## 10. Shared rules

These rules are implemented once in the core and used by the writer and every reader.

### 10.1 Paths (`path` of an entry)

A path MUST be rejected when any of these holds. Several rules reject names that would be safe on
some systems: this is deliberate (fail closed against the Win32 path normaliser, NTFS, APFS and
Linux), and may be relaxed only by a format revision.

- It is empty, longer than 1024 bytes, or deeper than 32 components.
- It is not in Unicode NFC.
- It starts with `/`, or has an empty component (`a//b`, a trailing `/`).
- A component is `.` or `..`, or is longer than 255 bytes (UTF-8).
- It contains `\`, NUL, a C0 control character (U+0000–U+001F) or DEL (U+007F).
- It contains any of `<` `>` `:` `"` `|` `?` `*` (so drive letters, `\\?\` and UNC forms and NTFS
  alternate data streams cannot appear).
- A component ends with `.` or a space.
- A component is a Windows device name, in any case, with or without an extension and with or
  without trailing spaces before the extension: `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`,
  `COM0`–`COM9`, `LPT0`–`LPT9`, `COM¹` `COM²` `COM³`, `LPT¹` `LPT²` `LPT³` (for example `con`,
  `Con.txt`, `CON .txt`, `lpt¹.log`). Names that only start with one are allowed (`CONSOLE`,
  `nul1.txt`, `com10`).
- A component contains `~` followed by an ASCII digit (an 8.3 short-name look-alike such as
  `PROGRA~1`). Over-rejects on purpose.
- A component's NFKC form contains any of `/ \ : * ? " < > |`, or is `.` or `..` (for example
  U+FF0E U+FF0E, U+FF3C). Over-rejects on purpose.

Accepted examples: `bin/app`, `Contents/MacOS/App`, `a b/c.d.e`, `ünïcode/文件` (NFC), `CONSOLE`,
`nul1.txt`, `com10`, a 255-byte component.

### 10.2 Trees (the entry set of one manifest)

- **Case folding.** No two entries have equal fold keys, where `fold(p) = NFC(lowercase(uppercase(p)))`
  with Unicode full case mapping, applied repeatedly until the string stops changing (one pass is
  not stable for U+1E9E: it gives `ß`, which gives `ss`). So `A` and `a`, `Straße` and `STRASSE`,
  `ẞ` (U+1E9E), `ß` and `ss`, `K` (U+212A KELVIN SIGN) and `k`, `Dir/x` and `dir/x` collide. Over-rejects on purpose: names that differ only in case or
  in case-folding forms are rejected even where the filesystem would keep them apart.
- **Nothing under a non-directory.** No entry's path has a proper prefix (by components, compared
  by fold key) that is a `file` or `symlink` entry (`a` as a file and `a/b`).
- **Symlinks** appear only on `macos-*` and `linux-*` targets; a symlink entry in a `windows-*`
  manifest MUST be rejected. A symlink `target`:
  - is non-empty, at most 1024 bytes, NFC, without `\`, NUL, C0 controls or DEL, and not absolute
    (does not start with `/`);
  - has no empty components;
  - resolves inside the tree. A stack of fold keys starts at the symlink's parent directory and the
    target's components are taken in order: `.` stays in place; `..` pops one component, and a `..`
    with nothing to pop leaves the tree (rejected); any other name is pushed, then looked up by fold
    key. When it names another symlink entry, that entry is a **hop**: its own target is resolved by
    this same rule, from its own parent, and the stack becomes where it led. So a later `..` pops
    the place the hop led to, not the hop's own place, as the kernel does. Hops are followed in any
    position, the last one included;
  - a hop that is not the last component ends on a directory: the tree root, a `dir` entry or an
    implied parent directory (a proper prefix, by fold key, of some entry). A hop ending on a `file`
    entry or on a name with no entry is rejected. The symlink's own end (after its last component
    and any final hop) may be any entry, an implied directory or a name with no entry (dangling);
  - follows at most `MAX_LINK_HOPS` = 8 symlink entries: the count of a symlink is the sum, over
    every symlink entry its resolution steps onto (each step counts), of one plus that entry's own
    count; a symlink whose target names no symlink counts 0. More is rejected. A hop into a symlink
    whose own resolution is in progress (a cycle, the symlink itself included) is rejected; a long
    cycle may be reported as too many hops first. 8 is far below the kernels' limits (32 on macOS,
    40 on Linux), so an accepted symlink never meets `ELOOP`.
  - Each symlink's target is resolved at most once per tree (memoised), so the check stays
    `O(n log n)` in the entry count plus the targets' bytes. Which symlink a rejection names follows
    the entry order; whether the tree is rejected does not.
  - Accepted: `Versions/Current` → `A`, `lib/x.so` → `x.so.1`, a framework's `Foo` →
    `Versions/Current/Foo` and `Resources` → `Versions/Current/Resources` with `Versions/Current` →
    `A` (one hop, ending on the directory `Versions/A`, listed or implied), `d/s` → `..` with `l` →
    `d/s/x` (the hop ends on the root; `x` dangles inside). A target inside the tree that names no
    entry (dangling) is allowed.
  - Rejected: `s` → `.` with `l` → `s/../x` (the hop leads to the root, and `..` then leaves the
    tree), `S` → `.` with `l` → `s/../x` (the hop is found by fold key), `y` → `w` with `w` a file
    and `x` → `y/z` (the hop ends on a file), `a` → `b/x` with `b` → `a/y` (a cycle), and a chain of
    nine symlinks each naming the next.

### 10.3 Versions

- A version is a SemVer 2.0.0 string of at most 64 bytes, without a leading `v`. Leading zeros in
  numeric parts and missing parts (`01.0.0`, `1.0`) are rejected.
- Versions are ordered and compared for equality by SemVer **precedence** only: build metadata is
  kept for display and ignored for ordering, so `1.0.0+a` and `1.0.0+b` are equal.
  `1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta < 1.0.0`.

### 10.4 Targets

The target ids of v1 are exactly:

`windows-x86_64`, `windows-aarch64`, `macos-x86_64`, `macos-aarch64`, `macos-universal`,
`linux-x86_64`, `linux-aarch64`.

Any other string (`linux-x86`, `Windows-x86_64`, `macos-arm64`) MUST be rejected. Fallbacks, tried
in order after the host's own id: `windows-aarch64` → `windows-x86_64`; `macos-x86_64` and
`macos-aarch64` → `macos-universal`. The others have no fallback.

### 10.5 Channels

A channel id is 1–32 bytes: `[a-z0-9]` first, then `[a-z0-9-]`.

### 10.6 App ids

An app id is 1–64 bytes: `[a-z0-9]` first, then `[a-z0-9._-]`; it contains no `..`, does not end
with `.`, and is not a Windows device name (10.1).

### 10.7 Relative references

See 7.1: the path rules of 10.1 plus ASCII `[A-Za-z0-9._+-]` per component.

## 11. Verification order and policy

### 11.1 Order

A reader checking for an update runs these steps in order; a failure stops the check, reports a
typed error and changes no state:

1. **Root.** Start from the trusted root (5.2) and walk `root-<k>.json` documents.
2. **Key set.** Open `keys.json` (2.6) with the root's keys and threshold; check `app_id`,
   `root_version`, the key-set floor, expiry and the key rules (6).
3. **Feed.** Open `feed-<channel>.json` with the key set's release keys valid at `now` and its
   release threshold; check `app_id`, `channel`, the seq floor, expiry, release uniqueness and the
   references (7).
4. **Candidate.** Select a release (11.4). No candidate: done, no update.
5. **Manifest.** Fetch at most the referenced `size` bytes; check length and SHA-256 against the
   feed; open the envelope with the release keys; check `app_id`, `version`, `target`, the tree
   (10.2) and every frame descriptor against `pack.size` (9).
6. **Files.** Fetch frames (or the pack) bounded by the signed sizes, and decode per 9.2.

Every document runs 2.6's order: size cap → strict JSON → envelope → payload type → signature
threshold → only then the payload parse → `format`, `kind`, `critical` → binding (app id, channel,
target, version, hash and size from the feed) → rollback floors → freshness. A verified value is
produced only after all of them pass.

### 11.2 Anti-rollback floors

The reader persists, per app, the highest values it has verified:

- the root version (5.2);
- the key-set `version`;
- the feed `seq`, per channel.

A document below its floor MUST be rejected; equal is allowed. After a check verifies documents,
the floors are raised to their values. Where the floors are persisted (the install-state record and,
for a per-machine install, the per-user counters records) and how a reader treats that record is
section 12.

### 11.3 Freshness and the implausible clock

- `now` comes from the reader's clock only (in the core, the `Clock` trait), never from a document.
- The key set is expired when `expires` is present and `now ≥ expires`; the feed likewise. Expired
  means "no update" and a reported error, never a downgrade.
- **Implausible clock.** The caller supplies a floor time: the `issued` of the installed release's
  manifest (none on a first install). When `now` is earlier than that floor, the clock is
  implausible: the expiry checks and the release-key validity windows are skipped, and the verified
  result reports that they were skipped. Every other check still runs.

### 11.4 Candidate selection

From the verified feed, the candidate is the release with the highest precedence such that:

- its version is strictly newer than the installed version by precedence (equal is not newer;
  never a downgrade);
- it is not marked bad locally (a version that failed its health check);
- it lists the host's target, or else its first available fallback (10.4), and that target is used;
- the install is inside its rollout (11.5).

A pre-release is a candidate only because the channel's feed lists it; there is no channel-switch
logic in the format.

### 11.5 Rollout bucket

- The install id is 16 random bytes generated by the reader at install time and never sent anywhere.
- `bucket = u64_be(SHA-256(install_id ‖ seed)[0..8]) mod 10000`, where `‖` is concatenation of the 16
  install-id bytes and the 32 seed bytes.
- The install is inside the rollout when `bucket < basis_points`. A release without `rollout` is
  inside for everyone; `basis_points = 0` is inside for no one; `10000` for everyone.
- Known answer: install id `000102030405060708090a0b0c0d0e0f` and seed
  `44abc528db54f66d40174cfcdd43bab36285a5d953cbd185c672350a46f89691` give the first 8 hash bytes
  `f728fb2e5aacef3c` and bucket `6700`.

## 12. Install state

An install keeps what it knows about itself (its versions, the staged tree, the versions marked bad
and the anti-rollback floors of 11.2) as numbered **records**. Unlike sections 2 to 9 these are not
signed documents and the packager never writes them: the writer is the reader side (the in-app
library, and later the runtime and the privileged engine). The record is a **cross-version
contract** (D28): one lunepack version writes it and another reads it, after an update or a
rollback, and the Windows stub (C5) reads it too. A per-user install's state is writable by that
user (THREAT-MODEL class 4), so a reader treats every record as untrusted local input and checks
every rule below, failing closed.

### 12.1 Files

- A store is one directory. Each record is its own file, `<seq>.rec`, where `<seq>` is the record's
  sequence number in exactly 20 decimal digits, zero-padded (`00000000000000000007.rec`), and
  `seq ≤ 2^53 − 1`.
- A record file is created once and never rewritten, renamed or appended to; a change is a new
  record with the next `seq`.
- Any other name (including a 20-digit name above `2^53 − 1`) is not a record. Readers ignore it
  and writers never delete it.

### 12.2 Frame

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic, the ASCII bytes `LPST` |
| 4 | 1 | frame format, `1` |
| 5 | 4 | `len`, the payload length, unsigned big-endian |
| 9 | `len` | payload: strict JSON (12.3) |
| 9 + `len` | 32 | SHA-256 of every byte before it (magic through payload) |

A record file is at most 1 MiB (1048576 bytes) in all, and its length is exactly `9 + len + 32`.

### 12.3 Payload

The payload follows 3.1 with one difference: `null` is the value of a field the tables mark "or
null", and every field in the tables is required (a nullable field is written as `null`, never
omitted), except `last_run` of an `install-counters` record. Integers follow 3.1 (`0 ..= 2^53 − 1`).

Every record has:

| Field | Type | Rule |
|---|---|---|
| `format` | integer | `1` |
| `kind` | string | `install-state` or `install-counters` |
| `critical` | array of strings | v1 writes `[]` (12.8) |
| `seq` | integer | equals the `<seq>` of the file name |
| `app_id` | string | the app id (10.6); equals the app's own |

An `install-state` record also has:

| Field | Type | Rule |
|---|---|---|
| `scope` | string | `user` or `machine` (12.6) |
| `install_id` | string | the install id of 11.5: 32 lowercase hex characters |
| `target` | string | the target the install uses (10.4) |
| `current` | object or null | `{version, issued}`: the installed version and its manifest's `issued` (the floor time of 11.3); `null` before the first install completes |
| `previous` | object or null | `{version}`: the version installed before `current` |
| `pending` | object or null | `{version, attempts}`: a version waiting for its health check (written from M5) |
| `staged` | object or null | `{version, target, manifest_sha256, tree}`: a staged version tree (12.7) |
| `bad` | array of strings | versions marked bad (11.4), in strictly increasing precedence (sorted, no precedence twice), at most 1000 |
| `floors` | object | the floors of 11.2, below |
| `health` | object or null | `{version, token_sha256}`: the supervised launch of the pending version (12.9); `null` when there is none |
| `lifecycle` | object or null | `{events}`: lifecycle events not yet delivered (12.9), at most 16, oldest first; `null` when there are none |
| `staged_issued` | object or null | `{version, manifest_sha256, issued}`: the `issued` of the staged manifest (12.9) |

An `install-counters` record (12.6) has, besides the common fields, only `install_id`, `floors` and
`last_run`:

| Field | Type | Rule |
|---|---|---|
| `last_run` | version | the version this user last ran on a per-machine install (12.9); **optional**: the member is left out, never written as `null`, until the first run, and a record written before it existed lacks it. It is the one field of the tables above that may be absent |

`floors` is `{root, keyset_version, feed_seq}`:

- `root` is the highest verified root (5.2) as its parts, `{version, threshold, keys}`, or `null`
  before the first check. `version ≥ 1`, `1 ≤ threshold ≤ len(keys) ≤ 16`, each key 64 lowercase hex
  characters, no key twice. The parts are kept, not just the version, so the rotation walk starts
  from that root even when the host no longer has `root-<k>.json`.
- `keyset_version` is the highest verified key-set `version` (`0`: none).
- `feed_seq` maps a channel id (10.5) to the highest verified feed `seq`; at most 64 channels.

Further rules: every version is a version of 10.3; `staged.tree` is one path component that passes
10.1 and equals the text of `staged.version`; `staged.manifest_sha256`, `health.token_sha256` and
`staged_issued.manifest_sha256` are digests (3.2). Each entry of `lifecycle.events` is one of
`{kind: "installed", version}`, `{kind: "updated", from, to}` and `{kind: "first_run", version}`.
An object inside a record (`current`, `previous`, `pending`, `staged`, `floors`, `floors.root`,
`health`, `lifecycle`, an event, `staged_issued`) has exactly its listed members; an unknown member
there makes the record invalid (12.8).

`health`, `lifecycle` and `staged_issued` were added in M5 as top-level members (12.8 (a)), so a
record written before them lacks them: a reader takes a missing one as `null`. Every writer from M5
writes all three.

The lunepack writer emits the members of every object in byte order of their names. A reader does
not depend on member order. This example is generated by the writer (a test checks it):

<!-- golden: install-state, generated by crates/lunepack-core/tests/state.rs -->
```json
{
  "app_id": "org.example.hello",
  "bad": [
    "1.0.1"
  ],
  "critical": [],
  "current": {
    "issued": 1790000000,
    "version": "1.0.0"
  },
  "floors": {
    "feed_seq": {
      "stable": 42
    },
    "keyset_version": 3,
    "root": {
      "keys": [
        "fd60726cbdd246cb4f0e3363570e580a8af3c1a59eda73cf9c8672330459cb8f",
        "b960725ba13c46b7c70e3357e59a57fc7af3c2191d427457fc8672046509cb58"
      ],
      "threshold": 1,
      "version": 2
    }
  },
  "format": 1,
  "health": null,
  "install_id": "000102030405060708090a0b0c0d0e0f",
  "kind": "install-state",
  "lifecycle": {
    "events": [
      {
        "from": "0.9.0",
        "kind": "updated",
        "to": "1.0.0"
      },
      {
        "kind": "first_run",
        "version": "1.0.0"
      }
    ]
  },
  "pending": null,
  "previous": {
    "version": "0.9.0"
  },
  "scope": "user",
  "seq": 1,
  "staged": {
    "manifest_sha256": "3eb81763329a6df94982c6816f9e82b0e59f232d945ff3d24733debc97d1e321",
    "target": "linux-x86_64",
    "tree": "1.1.0",
    "version": "1.1.0"
  },
  "staged_issued": {
    "issued": 1800000000,
    "manifest_sha256": "3eb81763329a6df94982c6816f9e82b0e59f232d945ff3d24733debc97d1e321",
    "version": "1.1.0"
  },
  "target": "linux-x86_64"
}
```

(The keys and digest in the example come from the test suite's fake hasher; they are not real
SHA-256 values.)

### 12.4 Reading

A reader loads the newest record that was completely written, or fails. It never returns an older
record while a newer whole one exists (M4-D23).

1. List the directory. A missing or empty directory has no record. The **next seq** is the highest
   record name plus 1 (1 when there is none), whatever the files hold, so the number of a torn file
   is never reused.
2. Try the record files from the highest `seq` down. A file whose kind is not a regular file, whose
   size is over the cap (read at most 1 MiB + 1 bytes), or that vanished is skipped. Any other read
   failure stops the load.
3. **Integrity checks; a failure skips the file** (it is torn, flipped or misnamed) and the next
   lower one is tried: the magic, a frame format byte of `0`, the length (`9 + len + 32` equals the
   file size), the SHA-256, and the payload's `seq` equal to the file name's. (The payload is parsed
   to read `seq`; a payload that fails the strict JSON check or has no integer `seq` stops, as in
   step 5.)
4. **Newer format; stops the load**, with nothing written: a frame format byte above `1`, a payload
   `format` above `1`, or any entry in `critical`.
5. **A whole record that is refused stops the load**, with nothing written: the payload fails the
   strict JSON check (3.1), `format` is `0`, `kind` is not the expected kind, `app_id` is not the
   app's, a field is missing, unknown inside an object or of the wrong type, or a rule of 12.3 is
   broken. Its checksum shows a writer wrote it whole, so falling back to an older record (with lower
   floors) would be a rollback.
6. Otherwise the first record that passes is the state.

### 12.5 Writing

The writer holds the install's lock (M4-D15) from the load to the end of the commit.

1. The new record's `seq` is the next seq of 12.4 (at most `2^53 − 1`) and its `app_id` is the
   app's. No floor is lower than the loaded record's (field by field, as in 12.6). The writer runs
   12.4's checks over the bytes it is about to write and writes only what passes.
2. Create the file with create-new semantics; an existing file is a conflict and nothing is written.
   Missing directories of the store are created first, each synced in its parent.
3. Write the frame, sync the file, then sync the directory. The record is committed when the
   directory sync returns.
4. Only then prune, best effort: of the record files below the new `seq`, delete those that fail an
   integrity check (12.4 step 3) and the valid ones beyond the 3 highest valid (the new one counts).
   Leave every other file, including a record that would stop a load and any file whose name is not a
   record name.

A crash at any point leaves the previous record or the new one as the state, and the new one once
step 3 completed.

### 12.6 Scopes

- **Per-user install** (`scope: user`): one store in the install's state directory, read and written
  by the library.
- **Per-machine install** (`scope: machine`): the `install-state` store in the machine state
  directory, `R\.lunepack\state` (18.1; `R/.lunepack/state` on Linux and macOS, 20.1; world-readable,
  writable by administrators only), is written
  only by the privileged engine; the library reads it and never writes it. Each user keeps the floors
  they have verified for that install as `install-counters` records in
  `<user home>\state\<install_id as 32 hex>\` (18.5; `<user home>/state/<install_id as 32 hex>/` on Linux
  and macOS, 20.7). A counters record whose `install_id` differs from
  the machine record's is invalid (the load stops). A check starts from the **effective floors**: the
  key-set version and, per channel, the feed `seq` are the field-wise higher of the machine record's and
  the user's. The **root is never taken from a user's record** (M4-SEC-obs1, M10-D17): it is the machine
  record's `floors.root`, or, when that is `null`, the root of the installed tree's own update
  configuration (13.2), and a check walks any rotations again (5.2) each time, so a record a user can
  write never names a trust root. The engine reads the floors and the root from the machine record alone
  and has no parameter that names a user's directory. The machine record's root moves only when the
  engine stages an update (the machine learns a root rotation then); a user's check walks forward from the
  machine's root through the rotation documents the feed's host offers.

### 12.7 Trees on disk

- Version `V`'s tree is `<versions dir>/<V's version text>`; staging builds it there (M4-D18).
  Version texts that differ only in ASCII letter case (`1.0.0-RC1`, `1.0.0-rc1`) are different
  versions but one directory on a case-insensitive file system, so staging refuses a version whose
  directory name collides, ignoring case, with the current, previous, pending or staged version's, or
  with any entry of the versions directory (`Error::VersionDirCollision`); nothing is written.
- The **current tree** is the layout's explicit current tree when one is given (for a layout whose
  live tree is not under the versions directory), else `<versions dir>/<current.version text>`. It
  counts only when it is a real directory (a symlink is not followed); otherwise there is none and
  every file is fetched. A machine install's tree is only read.
- The directory names above (`versions`, `state`, `cache`, `logs`, the `current` link) are those of the
  Linux per-user layout. A Windows per-user install uses the names of section 16 (`app`, `.lunepack\state`,
  `.lunepack\cache`, `.lunepack\logs`, no `current` link). A macOS per-user install keeps the Linux names
  under another data home, has no `current` link, and holds its live version in a bundle outside the
  versions directory (section 17); its current tree is that bundle, the explicit current tree above, and
  every other kept version's tree is in the versions directory as before. A reader recognises an installed
  tree by its parent directory being the versions directory of one of the three schemes, or, on macOS, by
  it being the bundle the install's pointer names (section 17). A per-machine install uses the names of
  section 18 on Windows and of section 20 on Linux (`app/<ver>`, `.lunepack/state`, and the link
  `current`) and macOS (`app/<ver>`, `.lunepack/state`, the bundle of 17 as its live tree); a reader finds
  one by where the running tree stands and by the machine record, never by these names alone (20.1).
- A `staged` entry is usable only when `staged.version` is newer than `current.version` by
  precedence, is not in `bad`, `staged.target` equals the record's `target`, and the tree directory
  `<versions dir>/<staged.tree>` exists as a real directory. Otherwise it is ignored and the next
  staging resumes or discards the tree.

### 12.8 Evolution

- (a) Within `format: 1`, an unknown **top-level** member is ignored by readers and kept verbatim by
  every writer through every change of the record. An unknown member inside a known object makes the
  record invalid, so new data is added as new top-level members. A writer that adds a member older
  readers must not ignore names it in `critical`; a reader that finds a name it does not implement in
  `critical` stops (12.4 step 4). v1 implements no critical name.
- (b) `format` (frame byte and payload) is raised only for a change an older reader cannot handle by
  (a): a frame layout change or a changed meaning. Additive changes never raise it; no raise is
  planned for v1.
- (c) An older reader that meets a newer format fails closed and writes nothing; the library reports
  it from every operation. A build that raises the format keeps writing the old one until its own
  version is confirmed healthy, so a rollback before that never leaves a record the previous version
  cannot read.
- `health`, `lifecycle` and `staged_issued` are such members (M5, 12.9): an M4 reader keeps them
  verbatim. An `install-counters` record has no `health`; a reader keeps one it finds there as an
  unknown member, and when present it is an object or `null`.

### 12.9 Lifecycle members

- **`staged_issued`** names the staged entry it belongs to. It is **bound** only when its `version`
  is the text of `staged.version` and its `manifest_sha256` equals `staged.manifest_sha256`; its
  `issued` is then that manifest's `issued`. A writer that sets `staged` writes the bound value with
  it, and one that clears `staged` clears it. An older writer keeps it verbatim while it changes
  `staged`, so an unbound value (or a missing one) is read without error and counts as absent:
  applying the staged version needs a bound value, and without one the app stages again. A writer
  drops an unbound value with its next record.
- **Apply.** Applying the staged version `V` (usable by 12.7, with a bound `staged_issued`, no
  `pending`, and fewer than 1000 versions in `bad`) sets `previous` to the old current,
  `current` to `{V, staged_issued.issued}` (so the floor time of 11.3 is the running release's),
  `pending` to `{V, 0}` and `health` to `{V, SHA-256 of the token}`, and clears `staged` and
  `staged_issued`. The token itself is never written.
- **Confirm.** A start of the pending version confirms it: with a token whose SHA-256 equals
  `health.token_sha256` (a token that does not match changes nothing), or, per user, with no token.
  A confirmation clears `pending` and `health`.
- **Attempts.** An unsupervised start of the pending version adds 1 to `pending.attempts`; the start
  that would make it 4 rolls back instead.
- **Rollback.** Rolling the pending version back sets `current` to `{previous, current.issued}`
  (the floor time never decreases), clears `previous`, `pending` and `health`, adds the version to
  `bad`, and drops its events.
- **Events.** `installed` and `first_run` are queued by a first install, `updated` and `first_run`
  by an apply. Each is for one version (`version`, or `to` for `updated`) and is delivered at most
  once, by that version's first start, which removes it in the same record.
- **Events on a per-machine install** (M10-D16). The machine record queues none: the library cannot mark
  them delivered, and they would be one user's. It derives them per user from `last_run` in that user's
  `install-counters` record when this version starts: no `last_run` gives `first_run`; a lower one
  gives `updated` (from it) and `first_run`; an equal or higher one (after a rollback) gives nothing;
  `installed` is not delivered. The record is committed with `last_run` set to this version before the
  events are returned, so each is delivered at most once per user.

## 13. Update configuration

Every version tree that updates itself carries one **update configuration**: a strict-JSON file that
says which root, feed and channel the tree updates from and how the app is installed (D44 (a),
M5-D3). It is not signed on its own. It is an ordinary file entry of the release's manifest, so the
manifest's `sha256` of the file covers it, and staging (C3) checks that hash like any other file's.
Like the install state (section 12) it is a **cross-version contract** (D28): one version's runtime
reads another version's configuration. Every reader treats it as untrusted local input (an installed
tree is writable by its user) and checks every rule below, failing closed.

The packager writes it only for an app whose `lunepack.toml` has `[update]` (M5-D7). Its reader is
`lunepack_core::UpdateConfig::parse` and its writer `UpdateConfig::to_bytes`; the writer runs the
reader over the bytes it is about to write and writes only what passes.

### 13.1 Location

- On Linux and Windows targets the file is `lunepack-update.json` at the version tree's root
  (`<tree>/lunepack-update.json`). On macOS targets it is `Contents/Resources/lunepack-update.json`
  inside the bundle tree (M8-D1; section 17), in the bundle's resources folder, so a code signature seals it
  with the rest of the bundle.
- The location is fixed for format 1 and never moves within it, so any version's runtime reads
  another version's configuration at the same place (M5-D17). An executable finds its tree by
  walking up from its own directory to the nearest configuration; the packager refuses an input
  that holds a file of that name anywhere, so nothing shadows it.
- The runtime is `lunepack-runtime` (`lunepack-runtime.exe` on Windows targets) in the directory of
  `install.entry` (C4).

### 13.2 Payload

The file follows 3.1 with one difference: `null` is the value of a member the tables mark "or
null", and every member in the tables is required unless the table says "optional" (a nullable member is
written as `null`, never omitted; an optional member is left out when it has no value). It is at most 64 KiB (65536 bytes).

| Member | Type | Rule |
|---|---|---|
| `format` | integer | `1` |
| `kind` | string | `update-config` |
| `critical` | array of strings | v1 writes `[]` (13.7) |
| `app_id` | string | the app id (10.6); equals the root's app id |
| `version` | string | the tree's own version (10.3) |
| `target` | string | the tree's target (10.4) |
| `root` | object | the trusted root the tree updates under, as its parts `{version, threshold, keys}` (5.2): `version ≥ 1`, `1 ≤ threshold ≤ len(keys) ≤ 16`, each key 64 lowercase hex characters, no key twice |
| `feed` | string | the release directory's URL, by the feed rule (13.3) |
| `channel` | string | the channel the tree follows (10.5) |
| `health_timeout_secs` | integer | `5 ..= 3600`: how long a supervised start may take to confirm its health (the packager's default is 60) |
| `install` | object | the install metadata (13.4) |
| `publisher_check` | string, optional | the publisher-continuity policy of the tree (M9-D6, M9-D9): `off`, `warn` or `enforce` (exact, lowercase text; anything else, or a value that is not a string, is invalid). It tells the tree's own runtime what to do when it stages a later version whose OS code signature is not the installed one's (RUNTIME.md, "Publisher continuity"). Absent means `off`, so every configuration from before the member reads as `off`. The writer leaves the member out when the policy is `off` (never writes `"off"` or `null`), so the bytes of a configuration with no policy are the bytes from before the member existed |

The member governs the check of the **next** update only, and only the installed tree's own value counts: a
candidate's `publisher_check` takes effect once it is installed, never on its own staging (M9-D6). The
packager writes `enforce` when the config has a `[codesign.<os>]` section for the target's OS and no
`[update] publisher_check`, `off` otherwise, and an explicit `[update] publisher_check` wins (CLI.md, "Code
signing").

The lunepack writer emits the members of every object in byte order of their names, pretty-printed
with two-space indentation and a final newline. A reader does not depend on member order or
whitespace. This example is generated by the writer (a test checks it):

<!-- golden: update-config, generated by crates/lunepack-core/tests/update_config.rs -->
```json
{
  "app_id": "org.example.hello",
  "channel": "stable",
  "critical": [],
  "feed": "https://updates.example.org/hello/",
  "format": 1,
  "health_timeout_secs": 60,
  "install": {
    "bin": "hello",
    "categories": [
      "Utility",
      "Development"
    ],
    "comment": "Says hello",
    "entry": "bin/hello",
    "icon": "share/hello.png",
    "name": "Hello",
    "terminal": false
  },
  "kind": "update-config",
  "root": {
    "keys": [
      "fd60726cbdd246cb4f0e3363570e580a8af3c1a59eda73cf9c8672330459cb8f",
      "b960725ba13c46b7c70e3357e59a57fc7af3c2191d427457fc8672046509cb58"
    ],
    "threshold": 1,
    "version": 2
  },
  "target": "linux-x86_64",
  "version": "1.0.0"
}
```

(The keys in the example come from the test suite's fake hasher; they are not real keys.)

### 13.3 Feed

`feed` is the URL of the release directory, the one that holds `keys.json` and
`feed-<channel>.json` (section 1). It must pass every rule below, checked by the writer and by every
reader (M5-D16). A string that passes is already in the canonical form of the WHATWG URL parser, so
parsing it changes nothing and a check of the string is a check of what the transport connects to.

- At most 2048 bytes, every byte in ASCII `0x21`–`0x7E`: no space, tab, CR or LF (the WHATWG parser
  strips tabs and newlines silently), control or non-ASCII byte.
- None of `\ % ? # @ " < > ^ ` { | }` anywhere, so there is no userinfo, query, fragment,
  percent-encoding or backslash (which the parser reads as `/`).
- The scheme is lowercase and exactly `https://`, `http://` or `file:///`.
- An `https` host is lowercase LDH labels (each 1–63 bytes of `[a-z0-9-]`, not starting or ending
  with `-`, at most 253 bytes in all, no trailing dot) or a canonical dotted-quad (four decimal
  parts `0`–`255` without leading zeros). A host whose last label is all digits or starts with `0x`
  must be a canonical dotted-quad, because the parser reads `127.1` and `0x7f.1` as IPv4. A
  bracketed IPv6 host is refused for `https` in v1.
- An `http` host is exactly a canonical dotted-quad whose first part is `127`, or exactly `[::1]`.
  Nothing else: not `localhost` (a name the resolver maps, so its target cannot be proven), not
  another IPv6 spelling of loopback, not another address.
- A port is optional for `http` and `https`: decimal `1`–`65535`, no leading zero, and not the
  scheme's default (`443`, `80`), which the parser would drop.
- The path starts and ends with `/`. Its segments are `[A-Za-z0-9._~-]+` and neither `.` nor `..`.
  A `file:` path may start with one Windows drive segment `[A-Z]:` (`file:///C:/releases/`). The
  writer appends the final `/` when the configured value lacks it, then checks.

Why `http:` only to a loopback literal: release content is signature-verified whatever the
transport, but plain HTTP to another host would expose the update metadata and let a network
attacker hold an install on old metadata until it expires. Loopback stays on the machine (a local
mirror, the test suites' servers). An `http:` feed from the configuration is fetched with no proxy
(environment or system) and no redirect, because either could carry the request off the host.

The facade's `check_config_feed` is the authoritative check, run by the packager and before any
request: it applies these rules, then parses the string with the URL parser the transport uses, and
refuses unless the parsed URL serialises to the input byte for byte, its scheme is the one the rules
saw, it has no user name or password, and an `http` host parses to an IPv4 address with first octet
127 or to `::1`. The library's own `UpdaterBuilder` takes any feed URL as before; these rules bind
only a feed read from an update configuration.

### 13.4 Install metadata

`install` is `{entry, name, comment, icon, categories, bin, terminal}` (M5-D4), the optional
`publisher` (M6-D3) and the optional `file_types`, `url_schemes` and `autostart` (M7-D3), with exactly
these members; an unknown member makes the document invalid (13.7). A format-1 reader from before
`publisher`, or from before the three declarations, refuses a document that holds one of them;
nothing was released with such a reader.

| Member | Type | Rule |
|---|---|---|
| `entry` | string | the executable the runtime launches: a path (10.1) of at most 32 components; its file name is not `lunepack-runtime`, `lunepack-runtime.exe`, `lunepack-ui` or `lunepack-ui.exe`, and no component is `lunepack-update.json` (all compared ignoring ASCII case). The packager checks that it is a file with `exec` |
| `name` | string | the display name: 1 to 128 Unicode scalar values |
| `comment` | string or null | a one-line description: 0 to 512 Unicode scalar values |
| `icon` | string or null | a PNG or SVG file in the tree: a path as for `entry`, ending in `.png` or `.svg` (ignoring ASCII case) |
| `categories` | array of strings | freedesktop main and additional category names: at most 16, each `[A-Za-z0-9-]{1,64}`, no name twice |
| `bin` | string or null | the name of the command-line link (`~/.local/bin/<bin>` on Linux): `[A-Za-z0-9._-]{1,64}`, not starting with `-` or `.` |
| `terminal` | boolean | whether the app runs in a terminal |
| `publisher` | string, optional | the publisher's display name, shown by the installer beside "verified": 1 to 128 Unicode scalar values. The member is left out when there is no publisher (never `null`), so the bytes of a document without one are the same as before the member existed |
| `file_types` | array of objects, optional | file types the app can open: at most 32 objects `{ext, mime, name}`. `ext`: `[a-z0-9]{1,16}`, no dot, no `ext` twice. `mime`: `type/subtype`, each side `[A-Za-z0-9!#$&^_.+-]{1,127}`, no parameters (the same `mime` under two `ext` values is allowed). `name`: a display name, with the rule of `name` below (1 to 128). The member is left out when the array is empty (never `[]`) |
| `url_schemes` | array of strings, optional | URL schemes the app handles: at most 8, each `[a-z][a-z0-9+.-]{0,31}`, none twice, none on the deny-list below. Left out when empty |
| `autostart` | boolean, optional | whether the app starts when the user signs in. Left out when `false` (never written as `false`) |

A reader accepts the explicit empty forms (`[]`, `false`) of the three optional declarations as the absent
form; the writer never writes them, so a document without declarations has the same bytes as before
the members existed. Every violation names the member and the rule, never the value.

The deny-list of `url_schemes`, compared ignoring ASCII case: `about`, `blob`, `chrome`, `cid`, `data`,
`file`, `ftp`, `ftps`, `gopher`, `http`, `https`, `irc`, `javascript`, `ldap`, `ldaps`, `mailto`,
`microsoft-edge`, `mid`, `news`, `nntp`, `res`, `search-ms`, `sftp`, `shell`, `sms`, `ssh`, `tel`,
`telnet`, `urn`, `view-source`, `vbscript`, and every scheme starting with `ms-`.

The declarations are requests, not claims on the system: an integration offers the app as a handler
(Linux: `MimeType=` entries in the desktop entry, `x-scheme-handler/<scheme>` for a scheme, and an XDG
autostart entry; the Linux desktop entry then ends its `Exec` with `%U`) and never sets a default
handler. `name` in a file type is shown where the OS has a place for it and is otherwise unused.

`name`, `comment`, `publisher` and a file type's `name` hold no C0 or C1 control character, no DEL, no U+2028
or U+2029, no `\`, and no leading or trailing whitespace, so none can break a line of a desktop entry or
start an escape.

On Windows (section 16) the same declarations are written under the current user's registry only: a file
type is an "Open with" candidate (a ProgID `<app id>.<ext>` and a value of that name in
`HKCU\Software\Classes\.<ext>\OpenWithProgids`; the extension's own default value and the user's choice
are never read or written), a URL scheme is a protocol class whose command is `"<stub>" "%1"`, so the
system puts the URL in one quoted argument and the stub passes the command line on unchanged (section 15),
and `autostart` is a value named by the app id in
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. A launcher that substitutes the URL into the
command without escaping it can split a URL holding `"` into several arguments, so the app may receive more
than one. An app that declares `url_schemes` takes the first argument as the URL only when it starts with
one of its own schemes and `:`, and ignores or refuses every later argument, never reading one as its own
flag. `bin` is not used on Windows (no command link and no `PATH` change), and no desktop shortcut is made.

For a `windows-*` target the display name is also a Windows folder and shortcut name, so `name` must pass
one more rule (M7-D15), in this order; the packager refuses a `windows-*` pack or setup file that breaks it,
naming the field and the clause and never the value, and a Windows install or setup refuses it again:

1. at most 64 UTF-16 code units;
2. none of `< > : " / \ | ? *` and no character below U+0020;
3. no leading `.` or space and no trailing `.` or space;
4. its stem (the part before the first `.`, trailing spaces removed) is none of `CON`, `PRN`, `AUX`, `NUL`,
   `CONIN$`, `CONOUT$`, `COM0` to `COM9`, `LPT0` to `LPT9`, `COM¹`, `COM²`, `COM³`, `LPT¹`, `LPT²` or `LPT³`,
   compared ignoring ASCII case.

The rule validates and never rewrites a name. It is not applied to other targets.

For a `windows-*` target the file name `lunepack-stub.exe` (any ASCII case, at any depth of the input tree) is
reserved for the launcher stub the packager places beside the entry (section 15) and is an error in the input.

**macOS (M8).** For a `macos-*` target `entry` is `Contents/MacOS/<file>` (an executable regular file), so the
runtime lands in `Contents/MacOS` beside it, and the bundle's file name is chosen from `name` at the first
install (section 17). `name` can be that file name when `macos_name_ok` accepts it: 1 to 200 UTF-8 bytes, no
`/`, `:` or control character, and no leading `.`. The rule validates and never rewrites a name. Unlike the
Windows rule it does not refuse a release: a `name` that fails it makes the bundle's name the app id, and the
packager says so on stderr, naming the rule and never the name. The declarations are not all applied:
`autostart` writes a LaunchAgent property list (`~/Library/LaunchAgents/<app id>.lunepack.plist`, whose `Label`
is the same text and whose program is the entry inside the live bundle; it is never loaded, so it takes effect
at the next sign-in); `file_types` and `url_schemes` are not applied, because macOS takes them from the app's
own `Info.plist`; `bin` and the freedesktop members have no meaning there, and no shortcut is made. A file is
lunepack's only when it is a regular file whose `Label` is this app's; anything else at that path is a conflict
and is never overwritten or removed. The names `lunepack-runtime` and `lunepack-ui` in `Contents/MacOS`, the
file name `lunepack-update.json` at any depth, `Contents/Helpers/lunepack-update.app` with everything under it
and `Contents/Resources/lunepack-setup.payload` are reserved for what the packager places (`docs/CLI.md`,
"macOS targets") and are errors in the input.

### 13.5 Desktop-entry paths

A path the Linux integration writes into a desktop entry's `Exec` or `Icon` value (the absolute path
of the entry or icon under the install root) must be non-empty, with every character printable and
none of `" ` $ \ % '`; controls, U+2028/U+2029 and invisible format characters are refused. The rule
is `lunepack_core::desktop_safe_path`, shared by the writer's callers and the integration, so the
value never needs quoting beyond the double quotes of the specification and never expands.

### 13.6 Reading before staging

M5 reads the configuration only from a tree on disk: `install` runs from a bootstrap tree that
already holds the file, and the applier reads the new version's configuration from its staged tree.
A client that needs `name` or `icon` before any tree exists (the setup file's runtime, section 14)
reads them through the verified manifest:

1. Verify the chain to the manifest (11.1). The configuration is the manifest's file entry at its
   fixed path (13.1).
2. Take that entry's frame `{codec, offset, length, sha256}` (9.0) and read
   `pack[offset .. offset + length]`, by an HTTP Range request or from the installer's payload.
3. Check the frame's `sha256`, decode it under the signed caps (9.2), then check the file's `sha256`
   and `size` against the entry.
4. Parse the bytes with this section's reader. The icon file is read the same way.

### 13.7 Evolution

- Within `format: 1`, an unknown **top-level** member is ignored by readers (the reader keeps it and
  a writer that rewrites the document writes it back unchanged). An unknown member inside `root` or
  `install` makes the document invalid, so new data is added as new top-level members, or as new
  optional members of `install` in a revision that names them.
- `publisher_check` (M9) is such a top-level member: a reader from before it keeps it as an unknown member and
  ignores it, so an older runtime never enforces a policy it does not know. A reader that knows the member
  refuses a value outside `off`, `warn` and `enforce`.
- A writer that adds a member older readers must not ignore names it in `critical`. A reader that
  finds any name in `critical` stops with "newer format"; v1 implements no critical name.
- `format` above 1 is a newer format: the reader stops and nothing is written. `format` 0 is invalid.
- Every refusal names the member or rule; no value from the document is shown in an error.

## 14. Setup file

A setup file installs one release of one target with no network. It is the release's own runtime
(the `lunepack-runtime` file entry beside the entry, 13.1, taken from the pack through its signed
frame), then the payload, then a trailer:

```
runtime ‖ keys.json ‖ <ver>/<target>.manifest.json ‖ <ver>/<target>.pack ‖ trailer
```

Each payload part starts at an offset that is a multiple of 8 (zero bytes fill the gaps) and holds
the release directory's file byte for byte. The trailer also starts at a multiple of 8 (zero bytes
follow the last part), so the file's length is a multiple of 8: Authenticode pads to 8 before a
certificate table, and a signed file then keeps the trailer as the last bytes before the table. The writer is `lunepack setup` and its output is a
function of the release directory (and, for a Windows file, of its output file name, which the stamped
runtime carries); it is named `<app_id>-<ver>-<target>-setup`, with `.exe` appended
for a `windows-*` target. Linux and Windows targets have setup files in this revision; a macOS target has
an installer app that carries the same payload as a file of its own (14.4).

On Windows the runtime part is the release's `lunepack-runtime.exe`, taken from the pack through its signed
frame, with any certificate table removed and the app's icon and version information stamped in (the
stamp keeps the machine, subsystem, import table, `DependentLoadFlags` and manifest of its input, and the
writer checks that it did). Nothing follows the trailer. A setup file may then be signed with Authenticode
(its certificate table is appended after the trailer, which the signature covers); 14.3 says how a reader
finds the trailer in a signed file.

### 14.1 Trailer

The trailer is the last 4096 bytes of the file: a body area (4016 bytes), then an 80-byte footer.
Integers are unsigned little-endian.

| Offset in the footer | Size | Field |
|---|---|---|
| 0 | 4 | `format`: 1 |
| 4 | 4 | body length, 1 to 4016 |
| 8 | 8 | reserved, zero |
| 16 | 16 | key set: offset, length (8 each) |
| 32 | 16 | manifest: offset, length |
| 48 | 16 | pack: offset, length |
| 64 | 16 | magic: `89 4c 55 4e 45 50 41 43 4b 53 45 54 55 50 0d 0a` (`\x89LUNEPACKSETUP\r\n`) |

The body is canonical compact JSON (no whitespace, members in byte order) with exactly these
members, followed by zero bytes to the end of the body area:

```
{"app_id":"org.example.hello","root":{"keys":["<64 hex>"],"threshold":1,"version":1},"target":"linux-x86_64","version":"1.2.0"}
```

`root` is the trusted root the release's update configuration names (13.2: `keys`, `threshold`,
`version`), `app_id` its app id, and `version` and `target` the release the payload installs.

### 14.2 Reading

A reader looks only at the last 4096 bytes of its own resolved executable, or, for a signed Windows
executable, at the 4096 bytes before its certificate table (14.3). Without the magic there the file is not
a setup file. With the magic, everything else MUST hold or the file is refused
(the runtime's exit 7 `verify`; it never falls back to another mode):

1. `format` is 1 (another is a newer format); the reserved bytes are zero; the body length is in
   range and every byte after the body in the body area is zero.
2. The body is strict JSON (3.1) with exactly the four members; re-encoding it gives the same bytes;
   `root` is a valid root (5) of `app_id`; `version` is a version (10.3) and `target` a target id
   (10.4).
3. Every part is non-empty, starts at a multiple of 8 and ends at or before the trailer's first
   byte; the key set and the manifest are within their caps (4); no two parts overlap.

The trailer itself is not signed. Its root is the trust anchor of the install, as the root compiled
into an installed tree is (13.2); the payload is then verified under it with first-install floors
(11.2: none), in 11.1 order and without a feed:

1. The key set under the trailer's root, its expiry included (6, 11.3).
2. The manifest under the key set, counting only release keys whose window holds the reader's
   `now`, with the key set's release threshold; then as section 8: its `app_id` is the key set's,
   its `version` byte-equal to the trailer's, its `target` equal to the trailer's. With no feed,
   the signatures take the place of the feed's hash binding, so the release keys' windows apply.
3. The pack part is the manifest's pack size and SHA-256 (7.1).
4. The update configuration is read from the pack before staging (13.6) and names the trailer's
   `app_id`, `version`, `target` and exactly the trailer's `root`.

The install then stages from the pack's frames, each checked against its signed SHA-256 (9.2), and
the staged tree's configuration again names exactly the trailer's root. The installed app trusts
the root that verified it, and its later updates come from the feed as usual.

A setup file stops installing when its key set's `expires` passes or its release keys' windows end.
A publisher builds setup files from a current release; nothing re-signs old ones.

### 14.3 Locating the trailer in a signed Windows file

An Authenticode signature adds a certificate table at the end of a PE file, so the trailer is then not
the last 4096 bytes. A reader opens its own executable once and reads through that one handle. It has two
candidate ends: the file's length, and, when the file is a PE whose certificate-table data directory is
non-zero and starts at or after 4096 and before the file's end, the start of that table. It then decides
by the magic (14.1):

1. The magic at neither candidate end: not a setup file, whatever the headers or the table look like. The
   file is an ordinary runtime and runs as one (this is what every runtime start does, so no layout may
   turn it into a refusal).
2. The magic before the certificate table: the table starts at a multiple of 8, is at least 8 bytes long
   and ends exactly at the end of the file, and the trailer lies after the PE's headers and section data.
   Setup data then ends at the table's start, and the trailer is the 4096 bytes before it, read as in 14.1
   and 14.2 with that end as the file's size. Any other layout is refused.
3. The magic at the end of a file whose certificate-table directory is non-zero (bytes added after a
   signature), or at the end of a file that begins `MZ` whose PE headers cannot be read: refused.
4. The magic at the end of any other file (an unsigned PE, an ELF): a setup file ending there.

A refusal is the runtime's exit 7 `verify`, never a run as an ordinary runtime. The trailer and every
part lie inside the bytes an Authenticode signature covers, so a signature protects them; a signature is
not what makes a setup file trusted (14.2: the trailer's root is).

### 14.4 The macOS installer's payload file

A `macos-*` release has no setup file. Its installer is an app, `Install <name>.app`, written by
`lunepack setup` into an LZMA-compressed disk image (M8-D7):

| Path inside the app | Holds |
|---|---|
| `Contents/MacOS/lunepack-ui` | the release's UI, the app's main executable, taken from the pack through its signed frame |
| `Contents/MacOS/lunepack-runtime` | the release's runtime, taken from the pack through its signed frame |
| `Contents/Resources/lunepack-setup.payload` | the payload file below |
| `Contents/Info.plist` | generated; `CFBundleIdentifier` is the app id with `_` written as `-`, then `.lunepack-installer` |
| `Contents/Resources/lunepack-installer.icns` | the release's `[macos] icon`, when it has one |

The payload file is a setup file without the runtime part: `keys.json`, the manifest and the pack, each
starting at a multiple of 8 and the first at offset 0, then the trailer of 14.1, so the file's length is a
multiple of 8. The runtime in `Contents/MacOS` is in setup mode when its resolved path is that one and the
payload file next to it is a regular file (not a link). A file at that place is meant to be a payload, so
a file that does not parse is refused as in 14.2 (exit 7), never read as "no payload". The payload is then
verified exactly as a setup file's (14.2: the trailer's root is the trust anchor, no feed, first-install
floors). The runtime goes in `Contents/MacOS` and not in `Contents/Resources`, so that signing treats it
as the nested executable it is (M8-D7, refining D35's wording). The UI is the main executable, and it
starts the runtime beside it as the engine, so a double-click opens the window.

The image is built by `lunepack setup`; the installer app carries no signature in this revision.

### 14.5 The anchor of a Windows setup file (M10-D4)

A `windows-*` setup file carries, in the runtime image that precedes the payload, one `RT_RCDATA` resource
(id 1) of exactly 104 bytes, the **anchor**: the eight bytes `89 4C 50 41 4E 43 0D 0A` (`\x89LPANC\r\n`),
then three SHA-256 digests of 32 bytes each: of the 4096-byte trailer block (14.1) as written, of the
key-set part, and of the manifest part (the pack is bound by the manifest, 14.2). `lunepack setup` stamps
the resource with the eight magic bytes and 96 zero bytes (the placeholder) when it builds the image,
writes the payload and the trailer, patches the 96 bytes in place with the real digests, and reads the
file back against them; the file's length and the offsets of 14 do not change. An Authenticode signature
added afterwards covers the resource, as it covers the rest of the image.

A reader that installs for all users (the elevated engine; the unelevated run checks the same) reads the
anchor from the **mapped image of its own process**, not from the file, and refuses the payload before
anything is written unless, in this order: (1) the anchor is not the placeholder; (2) the SHA-256 of the
trailer block is the anchor's, before the trailer is parsed; (3) the trailer parses (14.1); (4) the key-set
part and then the manifest part, each read once within its cap, hash to the anchor's digests; (5) the
payload verifies as in 14.2 over exactly those bytes. The trailer's root is trusted because the anchor
names the trailer that carries it, never on its own.

What this binds: the payload to the image that was started and, after a User Account Control prompt, to the
image the administrator consented to, whatever happens to the file in a user-writable folder afterwards.
What it does not: a whole file swapped *before* the prompt. Only an Authenticode signature (CLI.md "Code
signing") lets the administrator tell a genuine `Setup.exe` from a swapped one, because then the prompt
names the publisher; an unsigned file shows "Unknown publisher" alike for both. `Setup.exe` is read only by
the runtime inside it, so the anchor is not a cross-version format and may change with the build.

## 15. Windows stub launch contract, version 2

The launcher stub is a small Windows executable that the packager stamps with the app's icon and version
information and places beside the entry as `lunepack-stub.exe`; the runtime copies it to the install
root as `R\<file name of install.entry>` whenever the current version changes (16). Shortcuts, the
uninstall entry and the declarations of 13.4 start that file. This contract is read by every stub of every
version against installs written by any other version (D28): once an app ships, a later stub and a later
runtime must keep both sides of it.

The stub takes `R` as the directory of its own resolved path (the final path of its executable) and from
nothing else: no argument, environment variable, registry value or folder name. It then:

1. Reads the newest whole install record under `R\.lunepack\state` (12; read only, no lock; each
   directory on the way is a real directory) and takes `current.version` from it. No record, or one with no
   current version, is exit 90; a record that cannot be read or is of a newer format is exit 91. A record of
   either scope, `user` or `machine`, is read the same way; any other scope text makes the record unreadable.
2. Reads `R\app\<current>\lunepack-update.json` (13) and takes `install.entry`. A missing, unreadable or
   invalid configuration, or one that does not name that version and the record's app, is exit 92.
3. Checks that `R\app\<current>\<entry>` is a regular file (else exit 93) and that no directory or file on
   the path below `R` is a symbolic link or reparse point (else exit 94). No link is ever followed.
4. Starts that file with the stub's own command-line tail passed through byte for byte, its environment
   and its current directory unchanged, and no job object. A failure to start it is exit 95.

The GUI stub (Windows subsystem) lets the child take the foreground and exits 0 without waiting. The console
stub (console subsystem) gives the child its console and standard handles, ignores Ctrl+C and Ctrl+Break in
itself (the child still receives them), waits, and exits with the child's exit code. The failures are shown
as one fixed message with no path or value from the install: a message box (GUI) or one line on standard
error (console).

Reserved: a command line of exactly `--lunepack-uninstall`, optionally followed by exactly one more argument,
`/S` or `--silent`, makes the stub start the current version's `lunepack-runtime.exe` (beside the entry) as
`uninstall`, with `--silent` for the optional argument, and exit 0. Any other command line, including the
same words in another position or case, goes to the app.

Changes from version 1: step 1 accepts a per-machine record (scope `machine`) as well as a per-user one;
version 1 refused it. Every other rule is unchanged. A version 1 stub answers exit 91 on a machine record,
which never happens in practice: a machine install is written only by a build whose stub is version 2.

## 16. Windows per-user layout

A per-user install on Windows has the install root `R` and these names inside it (cross-version contract
with section 15):

| Path under `R` | Holds |
|---|---|
| `<entry file name>` | the launcher stub (15) |
| `app\<version>\` | the version's tree (12.7) |
| `.lunepack\state\` | the install records and the lock (12) |
| `.lunepack\cache\` | the staging cache |
| `.lunepack\logs\` | the runtime's log |
| `.<entry file name>.old-<16 hex>`, `.<entry file name>.new-<16 hex>` | transient stub copies (below) |

There is no `current` link; the stub and the runtime read the record. `.lunepack` carries the hidden
attribute (set on every integration apply; nothing reads it).

**The folder name.** `R` is `<FOLDERID_UserProgramFiles>\<name>`, by default under
`%LOCALAPPDATA%\Programs`, where `<name>` is the app's display name `install.name` at its first install, which
must pass the Windows name rule of 13.4. The folder is chosen once and never recomputed: a later release
with another `name` keeps the folder, and an install is found by its record, not by its name.

To find or place an install of an app id, a first install or setup lists the entries of the programs folder
(at most 4096, else it refuses) and reads, read only, the newest whole record of every real directory whose
name does not start with `.` and that holds `.lunepack\state` (no link or reparse point is followed):

1. A record of this app id (per-user scope) in exactly one folder: that folder is `R`. In two or more:
   refused, because the user has copies of the install.
2. A record that cannot be read or is of another format is skipped, except in the folder named exactly
   `<name>` or `<name> (<app id>)`, where it is a refusal (installing beside it would make a second copy).
3. No match: `<name>` is used when it does not exist, is an empty real directory (adopted), or holds only what
   a first install cut off before its first record leaves (`.lunepack\state` with nothing but the lock and
   record-named files, no whole record: resumed). Otherwise (a file, a link or reparse point, a non-empty
   directory, another app's install) `<name> (<app id>)` is
   used under the same rule. When both are taken the install is refused (`install_mismatch`) and nothing is
   written; the entry that is in the way is never touched.
4. Every writer, under `R`'s lock and before its first write, checks that `.lunepack\state` holds no record of
   another app id.

**Uninstall** takes `R` from the uninstaller's own path and requires a real directory, not a reparse point,
whose canonical parent is the canonical programs folder and whose record carries this app's id. It does
not require that `R` is the only folder holding that record.

**Renaming the folder is not supported.** The stub and the runtime take `R` from their own paths, so an app
started from the renamed folder's stub still runs, but the Start-menu shortcut still points at the old
path, so lunepack no longer treats it as its own (a shortcut is lunepack's only when it carries the app id
and points at this install's stub): the next integration apply reports a conflict and leaves it until the
app is reinstalled.

**Stub placement.** On every integration apply (first install, an update, a rollback, a Setup rerun) the
stub at `R\<entry file name>` is made equal, byte for byte, to `R\app\<current>\<directory of the entry>\lunepack-stub.exe`.
When the file there is running (it cannot be replaced), it is renamed to `.<entry file name>.old-<16 hex>` and the
new copy moved in; on any error the old file is restored. A leftover `.old-` or `.new-` copy is removed by
a later collection once it is no longer running. A release whose entry has another file name gets a new stub
name, and the old stub (from the previous version's configuration) is removed when it is a regular file
directly in `R`.

**Shortcut, entries.** The Start-menu shortcut is `<Start menu>\Programs\<name>.lnk`; it carries the app id as
its app user model id and targets the stub. A shortcut, a registry key or a value is lunepack's only when it
carries this app's marker (the shortcut: the app user model id and the target; a key: a `LunepackAppId`
value naming the app id; a `Run` value: exactly the command lunepack writes); anything else is left alone
and reported. The uninstall entry is
`HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\<app id>` with `DisplayName`, `DisplayVersion`,
`Publisher` (when present), `DisplayIcon`, `InstallLocation`, `UninstallString` (`"<stub>" --lunepack-uninstall`),
`QuietUninstallString` (the same with `/S`), `NoModify`, `NoRepair` and the marker. `InstallLocation` is
written for Windows' sake and never read by lunepack.

## 17. macOS per-user layout

A per-user install on macOS has an install root `R`, outside the app, and a live app bundle `B`, which is
what the user sees and starts. The names below are a cross-version contract once an app ships (D28): the
runtime of one version reads the install another version wrote. Section 13.1 puts the update configuration
at `Contents/Resources/lunepack-update.json` inside every bundle tree.

| Path | Holds |
|---|---|
| `R` = `<data home>/<app id>` | the install root. The data home is the canonical `$HOME/Library/Application Support` (`HOME` absolute and UTF-8, canonicalised once) |
| `R/versions/<version>/` | the tree of every kept version other than the live one: a whole bundle tree named by the version's text (12.7), without `.app`, so no system service takes it for an app |
| `R/versions/.swap`, `R/versions/.out` | the two slots a tree passes through on its way into or out of `B` (17.3). Neither is a version's text, which starts with a digit |
| `R/state/`, `R/cache/`, `R/logs/` | as on Linux (12, 12.7) |
| `R/bundle` | an absolute symlink to `B` (17.1) |
| `R/bundle.id`, `R/bundle.id.tmp` | the identity of `B` (17.1); the second exists only while the first is being written |
| `B` = `<apps dir>/<bundle name>.app` | the live bundle: always the install's current version once a reconcile has finished |

There is no `current` link. The record (12) is the truth: which version is current, previous, pending or
staged. `B` and the trees are made to match it by renames only (17.3), and nothing else ever moves the
live app.

### 17.1 The pointer, the identity and the name of `B`

- **The apps folder** of a per-user install is `~/Applications`, canonicalised before `B` is chosen, and
  created with owner-only permissions when it is missing (M8-D2). A bundle the user later moves is
  followed (17.2).
- **`B`'s name** is chosen once, at the first install, and kept for the life of the install (as M7-D16): the
  display name `install.name` when `macos_name_ok` accepts it (13.4), else the app id, then `.app`. A name
  that is taken (any existing entry, which is never touched) falls back to `<name> (<app id>).app`, and when
  that is taken too the install is refused (`install_mismatch`, nothing written; as M7-D17).
- **`R/bundle`** holds `B`'s path as text: absolute, UTF-8, in normal form (no `.` or `..`, no doubled or
  trailing separator), the last name ending in `.app` with something before it, and every existing
  component of its folder a real directory and not a link. A pointer that is anything else, or `R/bundle`
  being anything but a symlink, is refused and never repaired. A runtime accepts a tree as the install's
  live bundle only when its canonical path equals the pointer's text byte for byte.
- **`R/bundle.id`** holds the device and inode of `B`'s directory as decimal text, `<device> <inode>`, at
  most 64 bytes, written through `R/bundle.id.tmp` and a rename. It is written after every placement and
  at the end of every reconcile that changed `B`, and rewritten by any reconcile that finds it not matching
  `B`, so a crash between a swap and the write heals at the next reconcile. It is how a bundle that the
  user moved is recognised (17.2); it is never used to decide which version `B` holds.

### 17.2 Where a running tree stands

A runtime that starts inside a bundle tree decides what it is in this order, before it reads the record's
state for any other purpose, and writes nothing while it does:

1. **Its location.** A tree on a `nullfs` mount, or under a path component `AppTranslocation`, is
   *translocated*; one on a read-only volume (a mounted disk image) is *read only*. Both are refused with the
   error `unsupported_location` (exit 28, `docs/RUNTIME.md`) in every mode, `check` included, so a
   translocated app always learns to move rather than being told it is not installed.
2. **A tree in `R/versions/` named by its own version text:** an old instance of this install (a process the
   previous version started before a swap keeps running from the path the swap gave its tree). It is
   installed.
3. **`R/bundle` names the tree.** The tree is the live bundle: installed, unless the record is *replaced*
   (17.4). When it names another existing bundle, the tree is a second copy of a live install and is not
   installed: one install per app id per user.
4. **The pointer is missing or its target is gone** and the tree is not under `$HOME/.Trash`: the install
   follows the move when the tree's device and inode are exactly those in `R/bundle.id` and the record is
   this app's, per user, with the tree's version as its current one. The follow happens under the install
   lock, which re-checks all of that, and re-points `R/bundle`. `startup`, `check`, `download`, `apply-and-restart`
   and `apply` each follow before they use the install, and a move that cannot be followed is `not_installed`
   (3), so an apply never recreates the bundle at the path it was moved from. A copy, a re-extracted archive, a move to
   another volume or a tree in the Trash has another inode and is not installed.
5. **Adoptable** (17.5): the tree's canonical parent is exactly `~/Applications` or `/Applications` and `R`
   holds no record, a record without a current version, or an orphaned or replaced one (17.4).
6. Otherwise **not installed**, a development run.

After the tree is accepted as `B`, a runtime that is about to change the install checks the place once
(`check_place`): `B`'s folder and `R/versions` are on one device (else `other_volume`); `B` is owned by the
caller (else `not_owned`; a root-owned `B` that is not the live bundle of a per-machine install of this app
(20.1, 20.5) is `machine_scope`, exit 17); the caller can create
entries in `B`'s folder (else `not_writable`). The folder itself need not be the caller's, so an
administrator's app in `/Applications` keeps updating (M8-D4).

### 17.3 Reconcile: making `B` hold the current version

The record is committed first (12.5), and reconcile then moves the disk to match it. It makes `B` hold
`current.version` using only the renames below, so the state after a crash at any point is one the next
reconcile finishes. Trees are identified by the app id and version in their own configuration, never by
their names, and a link or a file at `B`, a slot or a version path is never followed (it is an error).

With `B` the live bundle, `S` the swap slot, `X` the out slot and `T` = `R/versions/<current>`:

1. `B` is missing (the first placement, or a two-rename cut short): the tree among `X`, `S` and `T` that
   holds the current version is renamed to `B`. None does: the install is *orphaned* (17.4), and nothing is
   moved.
2. `X` holds a tree: it is renamed to `R/versions/<its version>`.
3. `S` holds a tree: it is parked the same way when `B` already holds the current version or `S` holds a
   third version; when `S` holds the current version it is swapped with `B`.
4. `B` holds another version: `T` must hold the current version and is renamed to `S` (else `B` cannot be
   made current and nothing is changed).

A swap is `renamex_np(RENAME_SWAP)` on the pair `S`, `B`: one atomic step in which both names change
places. A volume that does not support it (HFS+ and exFAT answer `ENOTSUP`) gets the journaled two-rename
instead, `B` to `X`, `S` to `B`, `X` to `S`, whose journal is the slot names and the record. Which is used
is learned by trying, never by a prior query. Every rename is followed by a sync of the folders it changed.
At most 16 moves are made in one reconcile; more means the disk keeps changing under it and is an error.

End state, whichever the path: `B` holds the current version, `R/versions/<previous>` holds the previous
version when it is kept, both slots are empty, and `R/bundle.id` names `B`. Reconcile only renames. It never
copies, writes (but for the identity), or removes a tree: the only thing that deletes a version tree is
garbage collection (M5-D9, on `R/versions` only), and the only other deletion is an uninstall (17.6). A
tree that is in the way (a stray tree in a slot, a name already taken) is parked under its own version or
reported, never replaced.

The update is therefore: stage the new version's tree in `R/versions/<new>` (12.7, as everywhere), commit
`pending` and `current` in the record, then reconcile (`T` to `S`, swap `S` with `B`, park the old tree).
The running app's own files move with its tree, and the process keeps its open files; a start that finds
the record ahead of the disk finishes the swap before it goes on. A rollback is the same moves with the
previous version as the current one.

**Extended attributes (M8-D10).** The manifest has none (8.1), so a staged tree carries none, and a copy of an
unchanged file from the old tree copies its data and mode only: `com.apple.quarantine` is never carried into
a new tree. lunepack never sets that attribute and never removes it from the live bundle in place. A tree
swapped into `B` therefore has no quarantine attribute, as with any updater that does not quarantine what it
downloads. The first-launch assessment of the original install is the system's and is not changed.

### 17.4 Orphaned and replaced installs

- **Orphaned.** The record has a current version, but `R/bundle`'s target is missing and no tree in
  `R/versions`, the slots included, holds that version. This is what the user's drag of `B` to the Trash
  leaves. Reconcile reports it and moves nothing; a start is then not installed. An installer run over an
  orphaned install is a fresh install that keeps only the anti-rollback floors (the root, the key-set
  version and the feed `seq`, 11.2): previous, pending, bad versions and events start anew, with a new
  install id, and the run ends with `installed`, not `already_installed`.
- **Replaced.** A bundle at `B`'s own path whose configuration is this app at another version than the
  record's current, while none of `B`'s slots or `R/versions/<current>` holds the current version. The user
  dragged a newer download over the old one, or used Finder's Replace. It is treated as orphaned for what
  follows: never installed, adoptable in an apps folder (17.5), otherwise a development run (an installer
  run over it still ends `already_installed`: move the copy to the Trash first, which makes it the
  orphaned case). A same-version
  copy at the same path is the live bundle (its inode is recorded again at the next reconcile). A bundle at
  `B`'s path that differs from the record only because an update or rollback was cut after its commit is
  not replaced: reconcile finishes that.

### 17.5 Adoption

A bundle that is adoptable (17.2 step 5) is adopted by the update check, and only there (`check` and
`download`, `docs/RUNTIME.md`): never at startup, which has no network, and never for a copy anywhere
else. It proves the bundle is byte for byte a release signed under the root its own configuration names,
then records it as the install. The bundle is not written, moved or removed.

1. The root, key set and feed are verified and the floors raised as any check does; the release selected is
   exactly the bundle configuration's version for its target (none: `no_release`).
2. The release's manifest is fetched and verified, and `B` must equal it exactly: the same set of relative
   paths, compared as listed bytes and never through a lookup, file sizes, SHA-256, executable bits and
   link targets, no extra entry (an empty directory included), nothing followed. Any difference is a
   `verify` failure and nothing is committed.
3. The commit order, each step durable before the next:
   1. `R/bundle.id` (and `R/versions`, so the layout is whole);
   2. the integration (the LaunchAgent for `autostart`), before the record, as at a first install;
   3. the record: a first install transition for no record or one without a current version, the orphan
      transition (17.4) for an orphaned or replaced one, so the floors are kept and a new install id is
      written;
   4. `R/bundle`;
   5. a reconcile, which renames nothing because `B` already holds the current version.

Every cut is safe. A crash before step 3 leaves a record without a current version (or the old one) and the
bundle adoptable again; the next check starts over. A crash after step 3 leaves a current version, a
pointer that is missing or dangling, an identity equal to `B`'s: 17.2 step 4 follows it at the next
start, with no network. The one case that cannot be told from a Finder move is a same-version orphan cut
between steps 1 and 3: the next start follows it as a move and the install keeps its record, losing only
the new install id and the `installed` and `first_run` events.

### 17.6 The helper app, the installer and uninstall

- **The update window** is a helper app nested in every bundle packed with `--ui` (M8-D6):
  `Contents/Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui` with a generated `Info.plist`
  (`docs/CLI.md`). Nothing but the runtime sits in `Contents/MacOS` beside the entry.
- **The installer** is `Install <name>.app` (14.4). It installs into `~/Applications` by 17.1 and 17.3's
  first placement, with the record committed after the pointer and the identity (17.5's order).
- **Uninstall** takes `B` from the runtime's own path and requires it to be exactly what `R/bundle` names,
  then removes, under the install lock and with nothing started or changed unless every check passed and no
  process runs from `B` or from any tree in `R`: `B`, renamed to `.<app id>.removing-<16 hex>` in its
  folder and then deleted; `R`, renamed to its tombstone in the data home (as 16) and then deleted; and the
  LaunchAgent entry when its `Label` is the app's. Each leaves its path in one rename, so a cut-off uninstall
  leaves `B` and `R` whole or gone, `B` first.

## 18. Windows per-machine layout

A per-machine ("all users") install on Windows has an install root `R` under the Program Files known
folder and the names below. They are a **cross-version contract** with sections 12, 15 and 19: the stub
(15), the library, the runtime, the update service and every later build of each find the install by
them. A per-machine install exists only for a release packed with the update service
(`lunepack-service.exe`, CLI.md `pack --service`); without it an app installs per user only (16).

### 18.1 Directories

`R` is `<FOLDERID_ProgramFiles>\<name>`, with `<name>` the app's display name `install.name` at its first
install (it must pass the Windows name rule of 13.4); the folder is found and placed by the rule of 16 (the
programs folder there is the Program Files known folder here, and a record counts only when it is of scope
`machine`). The known folder is taken from the operating system's API, never from an environment variable.

| Path under `R` | Holds | Class (18.2) |
|---|---|---|
| `<entry file name>` | the launcher stub (15) | `R` |
| `app\<version>\` | the version's tree (12.7) | machine tree |
| `app\.gc-<16 hex>\` | a version tree being removed (transient; the engine removes it, or a later pass does) | machine tree |
| `.lunepack\state\` | the machine `install-state` records (12; scope `machine`), world-readable | machine tree |
| `.lunepack\logs\` | the update service's log | machine tree |
| `.lunepack\machine\` | the engine's private area: | admin only |
| `.lunepack\machine\lock` | the engine's lock file (held by the service, or by the one elevated mode that runs) | admin only |
| `.lunepack\machine\incoming\<random>\` | one folder per upload session: the documents and objects a client sent, before they are verified | admin only |
| `.lunepack\machine\service\<version>\lunepack-service.exe` | the service binary of a version, the file the service registration names (18.3) | admin only |

Directly under the Program Files folder, and only while an elevated first install or an uninstall runs, one
folder named `.lunepack-install-<32 hex>` (the payload copied out of the consented `Setup.exe`, 14.5) or
`.lunepack-uninstall-<32 hex>` (the uninstaller's copy of the runtime, deleted at the next restart). Both
are admin-only and carry nothing a later version reads. At uninstall `R` is renamed to the tombstone `.<app id>.removing-<16 hex>` in the Program Files folder
before it is deleted (an admin-only folder nothing refers to; a failed deletion leaves it).

### 18.2 Protection

Every directory the engine creates under Program Files is created with an explicit protected descriptor
(the owner and the entries are never inherited from Program Files, which carries an inheritable CREATOR
OWNER entry). Two classes:

- **machine tree** (`R`, `R\app` and the version trees, `R\.lunepack` and its `state` and `logs`): owner
  Administrators; full control for LocalSystem and Administrators; read and execute for Users and all
  application packages; every entry inheritable; no CREATOR OWNER or CREATOR GROUP entry;
- **admin only** (`R\.lunepack\machine` and below): the same without the entry for Users and application
  packages.

The engine checks `R`, `R\app`, `R\.lunepack`, `R\.lunepack\state` and `R\.lunepack\machine`, through a
handle opened without following a link, at the start of every operation, and refuses to act
(`not_protected`) unless: the owner is LocalSystem, Administrators or TrustedInstaller; a DACL is present;
no allow entry for any other account holds more than read, read-attributes, execute and synchronize rights
(an unknown right bit, a generic write and `MAXIMUM_ALLOWED` count as more); and, for the admin-only class,
no allow entry for any other account exists. Deny entries only remove rights and are not judged; an entry
type that is neither allow nor deny fails the check.

### 18.3 The service registration and the pipe

| Item | Value |
|---|---|
| service name | `lunepack-<app id>` |
| account, start type, process | LocalSystem, start on demand, its own process |
| image path | the absolute path `R\.lunepack\machine\service\<version>\lunepack-service.exe` in double quotes, no arguments |
| descriptor | Windows's default for a new service, owner Administrators, plus one allow entry for Users with exactly start, query-status and read-control; read back and judged after it is set (anyone outside LocalSystem, Administrators and TrustedInstaller may hold only reads, status, interrogate, start and a user-defined control), else the registration is deleted again |
| pipe name | `\\.\pipe\lunepack-<app id>` |
| pipe | one instance for the service's life, created first (a name that exists is an error), remote clients rejected, byte mode; owner LocalSystem; LocalSystem and Administrators full control; Users read data, write data, read extended attributes, read attributes, read control and synchronize: never the right to create an instance, write the descriptor or take ownership |

A client connects with the impersonation level set to identification (the service can identify the caller
and never act as it), reads the pipe's owner from the handle and, unless it is LocalSystem, closes it
without sending a byte. The service finds `R` from its own image path and from nothing else.

The service updates its own binary: after version N is confirmed healthy the running service copies N's
`lunepack-service.exe` from N's verified tree into `service\<N>\`, runs it once with `--self-test` (it must
check its own location and exit 0 within ten seconds), and only then points the registration at it; a
failed self-test leaves the old registration. The previous binary stays until the switch after that.

### 18.4 Registry, shortcut, policy

The per-machine integration writes what 16 lists for a per-user install, to the machine hive and the
all-users locations: the uninstall entry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<app id>`
(`UninstallString` and `QuietUninstallString` target the stub as in 16; `InstallLocation` is `R`), the
declarations under `HKLM\SOFTWARE\Classes` and the `Run` value under HKLM when the app declares them, and
the shortcut `<FOLDERID_CommonPrograms>\<name>.lnk` with the app id as its application user model id. The
marker rules of 16 apply: an entry that is not lunepack's is left alone and reported.

The administrator's policy is read, never written, from `HKLM\SOFTWARE\Policies\lunepack\<app id>`: two
`REG_DWORD` values, `DisableSelfUpdate` and `NoUpdateUi`. A missing key or value is off; a number other
than 0 is on; a value of another type is on; any read error other than "not found" is on.
`DisableSelfUpdate` makes the engine refuse `stage_begin` and `apply` (`disabled_by_policy`) and the
library report it before a download; `NoUpdateUi` makes the runtime show no update window.

### 18.5 The per-user home

Each user of a per-machine install keeps what the library needs in `<FOLDERID_LocalAppData>\lunepack\<app id>\`
(the same place a per-user install keeps its data, for the same app id):

| Path | Holds |
|---|---|
| `state\` | this user's lock, and `state\<install_id as 32 hex>\` with the `install-counters` records (12.6) |
| `cache\` | the download cache |
| `logs\` | the library's and the runtime's log for this user |

This location is a **cross-version contract**: every later library version must find the counters (12.6,
including `last_run`, 12.9) there. Another user's home is never read or written, and an uninstall removes
only the uninstalling user's.

## 19. Privileged service protocol, versions 1 and 2

The update service of a per-machine install (18.3 on Windows, 20.3 to 20.5 on Linux and macOS) and the copies
of the library and the runtime that talk to it share this protocol, over a named pipe on Windows and a unix
socket on Linux and macOS (19.8). It is a **cross-version contract** (D28): an app of any version may meet a
service of any other, and once an app ships, version 1 can only be extended. A new request, answer, member
or error code arrives only with a new protocol version; `status`, `confirm` and `rollback` stay in every
later version. The service never trusts what a client sends: it copies every byte into an admin-only
folder and verifies it there against the machine record (THREAT-MODEL, "Windows per-machine" and "Linux and
macOS per-machine").

### 19.1 Frames

A frame is a `u32` little-endian length `n` (`n ≥ 1`), then `n` bytes, the first of which is the **kind**:

| Kind | Name | Body |
|---|---|---|
| 1 | message | at most 65,536 bytes: strict JSON (3.1), one object, duplicate keys refused, integers `0 ..= 2^53 − 1` |
| 2 | data | 1 to 262,144 bytes of raw data |

A length that exceeds the kind's cap, another kind, an empty body, or a message that is not exactly one
JSON object is refused before anything is allocated for it. Data follows the message that announces it
(`stage_begin`, `put`), may be split into any number of data frames, and is read in full before the request
is answered.

The writer emits every message with its members in a fixed order: `type`; then `app` on requests; then the
members in the order of 19.3. A reader does not depend on the order. Every message has a closed member set:
an unknown or missing member, a wrong type or an out-of-range value is `malformed`.

### 19.2 Hello

The first message, in every version, has exactly these members: the client sends
`{"type":"hello","min":a,"max":b}` (the lowest and the highest version it speaks); the server answers
`{"type":"hello","version":v}` with the highest version both speak, or `{"type":"unsupported","min":a,"max":b}`
with its own range and closes. A hello that is not a well-formed message, or that does not arrive within
five seconds, is answered by closing the connection with no message.

### 19.3 Requests and answers

Every request carries `app` (the app id). A request for another app is answered `error{wrong_app}` and ends
the connection. After an answer the client may send another request on the same connection.

| Request (members after `type`, `app`) | Answer | Meaning |
|---|---|---|
| `status` | `status{current, previous, pending, staged, service, self_update_disabled}` | Reports the machine record: `previous`, `pending` (`{version, attempts}`) and `staged` are `null` when there is none; `service` is the running service binary's version. No secrets. |
| `stage_begin{channel, documents}` + data | `stage_ready{version}`, `no_update`, or an error | `documents` is the array of `{kind, bytes}` the data frames carry, concatenated in that order: `root` documents first (ascending, at most 16), then exactly one `keys`, one `feed` and one `manifest`; every size from 1 to FORMAT 4's cap for its kind. The service verifies the chain against the machine record's root and floors, raises the stored floors, and selects the update the feed offers this machine itself (11.4); the client's choice is never trusted. `channel` must be the installed tree's. |
| `put{kind, sha256, size}` + data | `put_ok` | Uploads one object (`kind` is `pack` or `frame`; from version 2 also `patch`, 19.9) of exactly `size` bytes (at least 1). Accepted only if the verified manifest lists exactly that hash and size; each object at most once; valid only after `stage_ready`. |
| `stage_commit` | zero or more `progress{done, total}`, then `staged{version}` or `need_fetch{paths, more}` | Builds the candidate's tree from the verified bytes, runs the publisher check (RUNTIME.md), records it as staged. `need_fetch` names (at most 64) release paths still missing; the client uploads them and commits again. At most three commits per connection. |
| `apply{version}` | `applied{version, token}` | Makes the staged version current and pending its health check and refreshes the launcher, the uninstall entry and the shortcuts. |
| `attempt{version}` | `attempt{outcome, ...}` | A start of the pending version without a token: `supervised`, or `counted{attempts, token}`, or `rolled_back{current}`, or `not_pending` (19.5). |
| `confirm{version, token}` | `confirmed` or `nothing_pending` | Marks the pending version healthy, then switches the service to that version's own binary and removes old versions nobody uses. |
| `rollback{version, token}` | `rolled_back{current}` | Goes back to the previous version and marks the pending one bad. |

In an `attempt` answer the members are `type` (`attempt`), `outcome`, then `attempts` and `token`
(`counted`) or `current` (`rolled_back`). A token is 64 lowercase hex characters (32 bytes); a version is
its text (10.3); `sha256` is 64 lowercase hex characters.

Closing the connection discards the session's upload folder and any partial tree.

### 19.4 Errors

`error{code}` carries one code of this closed set; `verify_failed` adds `class`. An error changes nothing
on the machine. `malformed`, `wrong_app` and `timeout` end the connection; every other error leaves it open.

```text service-v1-codes
malformed
wrong_app
busy
disabled_by_policy
not_protected
verify_failed
channel_not_allowed
not_in_manifest
size_mismatch
hash_mismatch
publisher_mismatch
pending_exists
nothing_staged
version_mismatch
not_pending
token_mismatch
bad_full
too_large
timeout
internal
```

```text service-v1-classes
signature
expired
rollback
hash
format
app_mismatch
```

`busy` is the engine's answer when another host (an elevated mode of the runtime) holds its lock; a second
client of the service itself waits for the pipe (on Linux and macOS, in the listening socket's queue, 19.8),
which serves one connection at a time. No message carries
a path of the file system, an operating-system error text, an install id, a token digest or key material;
`need_fetch` carries release paths, which are the manifest's relative entry paths.

### 19.5 The token and the supervision lease

At `apply` the service draws 32 random bytes, stores only their SHA-256 in the machine record (`health`,
12.9) and returns the bytes to the caller, the user's own applier. The applier starts the new version with
the token in its environment (never on a command line); the new version's first act when it is healthy is
`confirm`, and if it crashes or the time runs out the applier calls `rollback`. Comparison is constant
time; without the token nobody confirms or rolls back, so another user cannot interfere in someone else's
health window.

When the applier dies before the answer, the version stays pending and any start of it by any user calls
`attempt`. The service keeps a lease in memory for the version (the health timeout of that version's signed
configuration, clamped to 5 to 3600 seconds, plus 15 seconds, from the `apply` or the last counted
`attempt`). While it runs, `attempt` answers `supervised` and changes nothing. Otherwise the service counts
one attempt in `pending.attempts` (12.9), issues a fresh token so an instance that turns out healthy can
`confirm`, and starts a new lease; the call that would make the fourth attempt rolls the version back and
marks it bad (`rolled_back`). A restart of the service forgets the lease, which errs toward counting.

### 19.6 Deadlines and limits

The service waits at most five seconds for the hello, 30 seconds for each later frame, and ends a
connection after 30 minutes; it exits after 60 seconds with no connection and no lease. It serves one
connection at a time. Write waits are bounded as well, so a client that never reads cannot hold it.

### 19.7 Examples

One encoded frame per line: `<name> | <the frame's first five bytes in hex: the length, little-endian,
then the kind> | <the body>` (a data frame's body is shown in hex). The lines are generated by the
protocol's own encoder, and a test (`format_doc`) checks that this block equals the golden file
`crates/lunepack-core/tests/golden/service-v1.txt`, line for line.

```text service-v1
hello client | 2100000001 | {"type":"hello","min":1,"max":1}
hello server | 1d00000001 | {"type":"hello","version":1}
hello unsupported | 2700000001 | {"type":"unsupported","min":1,"max":1}
request status | 2c00000001 | {"type":"status","app":"org.example.hello"}
request stage_begin | c600000001 | {"type":"stage_begin","app":"org.example.hello","channel":"stable","documents":[{"kind":"root","bytes":300},{"kind":"keys","bytes":400},{"kind":"feed","bytes":500},{"kind":"manifest","bytes":600}]}
request put | 9200000001 | {"type":"put","app":"org.example.hello","kind":"pack","sha256":"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","size":1048576}
request stage_commit | 3200000001 | {"type":"stage_commit","app":"org.example.hello"}
request apply | 3d00000001 | {"type":"apply","app":"org.example.hello","version":"1.1.0"}
request attempt | 3f00000001 | {"type":"attempt","app":"org.example.hello","version":"1.1.0"}
request confirm | 8a00000001 | {"type":"confirm","app":"org.example.hello","version":"1.1.0","token":"abababababababababababababababababababababababababababababababab"}
request rollback | 8b00000001 | {"type":"rollback","app":"org.example.hello","version":"1.1.0","token":"abababababababababababababababababababababababababababababababab"}
answer status | a900000001 | {"type":"status","current":"1.1.0","previous":"1.0.0","pending":{"version":"1.1.0","attempts":1},"staged":"1.2.0-beta.1","service":"1.0.0","self_update_disabled":false}
answer status (nothing optional) | 7f00000001 | {"type":"status","current":"1.0.0","previous":null,"pending":null,"staged":null,"service":"1.0.0","self_update_disabled":true}
answer stage_ready | 2900000001 | {"type":"stage_ready","version":"1.1.0"}
answer no_update | 1500000001 | {"type":"no_update"}
answer put_ok | 1200000001 | {"type":"put_ok"}
answer progress | 2800000001 | {"type":"progress","done":3,"total":10}
answer staged | 2400000001 | {"type":"staged","version":"1.1.0"}
answer need_fetch | 4a00000001 | {"type":"need_fetch","paths":["bin/app.exe","lib/data.bin"],"more":false}
answer applied | 7000000001 | {"type":"applied","version":"1.1.0","token":"abababababababababababababababababababababababababababababababab"}
answer attempt supervised | 2a00000001 | {"type":"attempt","outcome":"supervised"}
answer attempt counted | 7f00000001 | {"type":"attempt","outcome":"counted","attempts":2,"token":"abababababababababababababababababababababababababababababababab"}
answer attempt rolled_back | 3d00000001 | {"type":"attempt","outcome":"rolled_back","current":"1.0.0"}
answer attempt not_pending | 2b00000001 | {"type":"attempt","outcome":"not_pending"}
answer confirmed | 1500000001 | {"type":"confirmed"}
answer nothing_pending | 1b00000001 | {"type":"nothing_pending"}
answer rolled_back | 2900000001 | {"type":"rolled_back","current":"1.0.0"}
answer error | 2900000001 | {"type":"error","code":"token_mismatch"}
answer error verify_failed | 3b00000001 | {"type":"error","code":"verify_failed","class":"rollback"}
data | 0500000002 | 0001feff
```

### 19.8 The transport on Linux and macOS

The frames, messages, requests, answers, errors, token, lease, deadlines and limits of 19.1 to 19.7 are the
same bytes over a stream socket of the unix family (`AF_UNIX`, `SOCK_STREAM`) in place of the pipe (M11-D2):
protocol version 1 is unchanged and the golden file of 19.7 serves all three systems. The client streams the
signed documents and the pack or frames through the socket; no file descriptor crosses it (no `SCM_RIGHTS`),
so the service never reads from a file, FIFO, device or socket a user chose.

The service is started by the init system and takes its listening socket from it (systemd, file descriptor 3;
launchd, the socket named `lunepack`; 20.4, 20.5); it serves one connection at a time and exits after 60
seconds with no connection and no lease (19.6). The init system keeps the socket, so the next client starts
the service again, and the lease of 19.5, which is in memory, is forgotten at the exit as it is at any
restart. A second client is not refused: it waits in the socket's queue until the first connection ends,
and a client whose hello does not arrive within its own deadline (ten seconds in the library and the
runtime) ends with `service_unavailable`, reason `timeout`. The server takes no decision from who the peer
is: any local user may talk to it. The client's checks of the socket and of the peer are 20.3.

### 19.9 Version 2 (M12-D6)

Version 2 is version 1 plus one value: `put` may carry `kind` `patch`, a delta patch of the manifest
(9.3). Every other request, answer, member, error code, deadline and limit is version 1's, byte for byte;
a build that speaks version 2 still speaks version 1 (its hello offers `1..=2`), so either side of any
build meets the other at the highest version both speak.

- In a session at version 1, `put{kind:"patch"}` is a member value outside version 1's closed set:
  `malformed`, and the connection ends. A version-1 client never sends one.
- At version 2, `put{kind:"patch", sha256, size}` is accepted only when the verified manifest has a delta
  whose `from` is, byte for byte, the text of the machine record's current version and that delta lists
  a patch with that `sha256`; otherwise `not_in_manifest`. `size` must be the patch's `length`
  (`size_mismatch`); a repeat is `malformed`, as for every object.
- The service never takes a base from the client: at `stage_commit` it reads the base of each patch from
  its own current tree, joined from the entry's path under the protected current tree, and checks and
  decodes it as 9.3 says: the open checks only the last component for a regular file of `base_size`
  (an intermediate link is not refused, and the tree's links come only from a signed manifest and are
  confined to the tree), and the base is hash-checked against the signed manifest before decode and the
  output against the entry's hash, so the binding is the hash check, not the walk. Its sources per file are, in order: the unchanged current file, an uploaded frame, the
  uploaded pack, an uploaded patch; so a frame or the pack a client sends after a failed patch always
  wins, and a patch that fails is answered as that path in `need_fetch`, like a missing frame.
- No message carries a file-system path or a base digest the manifest does not already hold, and no
  error code is new.

A client that meets a version-1 service uploads no patch: it fetches the frames of the files it planned to
patch before its first `stage_commit`.

## 20. Linux and macOS per-machine layout

A per-machine ("all users") install on Linux or macOS has an install root `R` in a fixed machine home and
the names below. They are a **cross-version contract** with sections 12 and 19, as 18 is on Windows: the
library, the runtime, the update service and every later build of each find the install by them. A
per-machine install exists only for a release packed with the update service (`lunepack-service`, CLI.md
`pack --service`); without it an app installs per user only (the layouts of 12.7 and 17). One set of
directory names serves both systems and Windows (18.1 uses the same ones); only the machine home, the
service file name and what is projected from the record differ.

### 20.1 Directories

`R` is `/opt/<app id>` on Linux and `/Library/Application Support/lunepack/<app id>` on macOS: the app id,
never the display name, directly under the machine home. The machine home is a constant of the build, never
read from the environment, an argument or a file.

| Path under `R` | Holds | Class (20.2) |
|---|---|---|
| `app/<version>/` | the version's tree (12.7); on macOS the whole bundle tree (17) | machine tree |
| `app/.gc-<16 hex>/` | a version tree being removed (transient; the engine removes it, or a later pass does) | machine tree |
| `current` | Linux only: a symlink whose text is `app/<current version>` (relative); what the entry, the desktop entry and the command link go through | with `R` |
| `bundle`, `bundle.id`, `app/.swap`, `app/.out` | macOS only: the pointer to the live bundle `B`, its identity and the two slots of the swap, as 17.1 and 17.3 define them (the slots are under `app/` here, not `versions/`) | with `R` and `app` |
| `.lunepack/state/` | the machine `install-state` records (12; scope `machine`), world-readable | machine tree |
| `.lunepack/logs/` | the update service's log | machine tree |
| `.lunepack/machine/` | the engine's private area: | admin only |
| `.lunepack/machine/lock` | the engine's lock file | admin only |
| `.lunepack/machine/incoming/<random>/` | one folder per upload session, as 18.1 | admin only |
| `.lunepack/machine/service/<version>/lunepack-service` | the service binary of a version | admin only |
| `.lunepack/machine/lunepack-service` | the **stable service link**: a symlink whose text is `service/<version>/lunepack-service` (relative); the path the init system starts. It is switched only by creating a new link beside it and renaming that over it, so there is no moment without a target | admin only |

The service binary is `lunepack-service` (no extension) on both systems. The version trees are placed from
the verified release by the engine; a macOS tree is a bundle whose update configuration is
`Contents/Resources/lunepack-update.json` (13.1), a Linux tree's is `lunepack-update.json` at its top.

Directly under the machine home, and only while an elevated first install or an uninstall runs, one folder
named `.lunepack-install-<32 hex>` (the payload copied out of the consented setup file or `.pkg` payload,
FORMAT 14) or `.lunepack-uninstall-<16 hex>` (the uninstaller's copy of the runtime). Both are admin-only and
carry nothing a later version reads; a cut-off one is swept by the next run. At uninstall `R` is renamed to
the tombstone `.<app id>.removing-<16 hex>` in the machine home before it is deleted (as 18.1), and on macOS
`B` to the same tombstone in its folder. The macOS home also holds `.installer/<app id>/` (the `.pkg`'s
payload, CLI.md, removed once the install ends) and `.policy/` (20.6).

**What is projected.** After every commit of the machine record (first install, apply, rollback, a service
that opens an install) the engine makes the disk say what the record says: on Linux the link `current`
names `app/<current version>`, replaced by a new link renamed over it; on macOS the live bundle `B` holds
the current version's tree, by the reconcile of 17.3 run by the engine as root. `B` is
`/Applications/<name>.app`, or `/Applications/<name> (<app id>).app` when that name is taken or `<name>` is
not a valid bundle name (17.1); an existing entry is never touched, both names taken refuses the install
(`install_mismatch`), and `/Applications` is never created or changed. The record is committed first; a crash
between the commit and the projection is finished by the next operation. A rolled-back or removed version
leaves the projection where the record says, never ahead of it.

**Scope is by location.** An install is per machine when the running executable stands in a tree of `R/app/`
(or, on macOS, is the live bundle `R/bundle` names) with `R` directly in the machine home, and the newest
record in `R/.lunepack/state` is of scope `machine` and names the app. Never an argument, an environment
variable, a unit or a property list.

### 20.2 Protection

Two classes, checked by the owner, the mode and the access control list of each directory, never through a
link:

- **machine tree** (`R`, `R/app` and the version trees, `R/.lunepack` and its `state` and `logs`): a real
  directory (not a link) owned by uid 0, with no write bit for others, a group write bit only when the group
  is gid 0 (on macOS also gid 80, `admin`), and no access control list (macOS: no extended ACL entry; Linux:
  no `system.posix_acl_access`). The sticky bit does not stand in for a missing write bit. Created with
  mode 0755;
- **admin only** (`R/.lunepack/machine` and below): a real directory owned by uid 0 with no bit set for group
  or others and no access control list. Created with mode 0700.

`create_dir` makes the directory with mode 0700, sets its owner to 0:0 and its exact mode, syncs it and its
parent, and then checks it as above, removing it again when the check fails; the default umask, a set-group-id
parent and inheritable ACLs never decide a mode. The engine checks `R`, `R/app`, `R/.lunepack`,
`R/.lunepack/state` and `R/.lunepack/machine` at the start of every operation and refuses to act
(`not_protected`) when any is not as its class says; the check of `R` also applies the machine-tree rule to
every directory above it up to `/` (`/opt`, `/Library`, `/Library/Application Support`, ...), so a group-
or world-writable ancestor stops the engine.

Everything else a root process makes (the version tree, the record's files, the integration entries) takes the
process's file-creation mask, and `pkexec` keeps the caller's. Every process of the runtime and of the service
that stands as root on Linux or macOS therefore sets its mask to `0o022` as its first action, so the tree is
readable by every user and writable by root alone whatever mask the session that started it carried.

### 20.3 The endpoint and the client's checks

| Item | Linux | macOS |
|---|---|---|
| socket | `/run/lunepack/<app id>.sock` | `/var/run/lunepack-<app id>.sock` |
| mode and owner | 0666, root:root, made by systemd | 0666 (`SockPathMode` 438), made by launchd |
| directory | `/run/lunepack`, mode 0755, owner root, made by systemd | the system's `/var/run` (`/private/var/run`, root:daemon 0775) |
| longest path | 107 bytes (`sun_path` is 108 with its NUL) | 103 bytes (`sun_path` is 104 with its NUL) |
| registration | two systemd units (20.4) | one LaunchDaemon (20.5) |

An app id of at most 64 bytes always fits. Mode 0666 lets any local user connect, as Windows grants Users
the pipe (M10-D10); the server decides nothing from who connects.

A client, **before it sends a byte**, requires that: the socket's directory is a real directory owned by uid
0 that no one but root's group (macOS: and `daemon`'s) can write; the socket path is a socket owned by uid 0;
and, once connected, the peer's effective user id is 0 (`SO_PEERCRED` on Linux, `getpeereid` on macOS). Any
other answer closes the connection with nothing sent and is `service_unavailable` with reason `untrusted`. A
socket that does not exist (after retrying for three seconds) is `not_installed`; a socket nobody listens on
is `disabled`. The service takes its listener from the init system and refuses to run without one: Linux,
file descriptor 3, which must be a listening unix stream socket bound to the path above; macOS, the one
descriptor `launch_activate_socket` returns for the name `lunepack`, which must be a unix stream socket;
started any other way it prints one line and exits 2. It reads no environment variable and takes no
argument but `--self-test`. It finds `R` from its own resolved image path, which must have exactly the shape
`<machine home>/<app id>/.lunepack/machine/service/<version>/lunepack-service` with `<version>` its canonical
text and the app id valid, and from nothing else; the machine home is compared with what the kernel names
it (`F_GETPATH` on macOS, the canonical path on Linux).

### 20.4 Linux: the units

Two units in `/etc/systemd/system`, written with mode 0644 through a temporary file and a rename (the service
unit first), after which `systemctl daemon-reload` and `systemctl enable --now lunepack-<app id>.socket` run.
The first line marks a unit as lunepack's: the registrar reads the service's image from a unit only when it
carries that line, exactly one `ExecStart=` and a path of the shape of the stable link, and otherwise reports
the registration as not its own. The service unit has no `[Install]` section: the socket starts it.
`ExecStart` is the stable service link of 20.1, so the unit never changes when the service updates itself.
Removal runs `systemctl disable --now` on both units, deletes both files, reloads systemd and deletes the
socket file `/run/lunepack/<app id>.sock` (a stopped socket unit leaves it behind), and nothing else.

```text systemd-socket-unit
# Written by lunepack; do not edit.
[Unit]
Description=lunepack update service socket of org.example.hello

[Socket]
ListenStream=/run/lunepack/org.example.hello.sock
SocketMode=0666
SocketUser=root
SocketGroup=root
DirectoryMode=0755
Accept=no

[Install]
WantedBy=sockets.target
```

```text systemd-service-unit
# Written by lunepack; do not edit.
[Unit]
Description=lunepack update service of org.example.hello

[Service]
Type=simple
ExecStart=/opt/org.example.hello/.lunepack/machine/lunepack-service
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
UMask=0022
```

`Accept=no` makes the service a single long-lived process that is handed the listening socket (M11-D3), so
the lease of 19.5 survives from `apply` to `attempt`. A path with a byte a unit file would need to escape
(a space, `%`, `\`, `$`, `;`, a quote or a control character) is refused at registration. `systemctl` runs with an empty
environment and an absolute path. The two tests in `crates/lunepack-os-linux/tests/format_doc.rs` check
that both blocks above equal the bytes the registrar writes.

The service updates its own binary as 18.3 says: it copies the new version's `lunepack-service` into
`service/<N>/`, runs it with `--self-test` (it must check its own location and exit 0 within ten seconds),
and only then renames a new link over the stable link; a failed self-test leaves the old link. The running
service keeps its old image until it exits; the next start follows the new link.

### 20.5 macOS: the daemon and the bundle

One LaunchDaemon: the property list `/Library/LaunchDaemons/lunepack-<app id>.plist` (root:wheel, mode 0644,
written through a temporary file and a rename), label `lunepack-<app id>`, loaded with
`launchctl bootstrap system <plist>` (a replaced job is booted out and waited for first; a bootstrap is tried
up to three times, a second apart) and removed with `launchctl bootout`. The program is the stable service
link of 20.1; there is no `RunAtLoad` and no `KeepAlive`: the socket starts it. The plist carries a
comment that marks it as lunepack's; the registrar reads the image from a plist only when it carries that
comment, one `ProgramArguments` string and a path of the shape of the stable link. When the signed install
metadata carries the app's bundle identifier the plist also holds `AssociatedBundleIdentifiers` with that one
string, so that System Settings shows the daemon under the app; otherwise the key is left out.

```text launchd-plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by lunepack; do not edit. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>lunepack-org.example.hello</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Library/Application Support/lunepack/org.example.hello/.lunepack/machine/lunepack-service</string>
	</array>
	<key>Sockets</key>
	<dict>
		<key>lunepack</key>
		<dict>
			<key>SockPathName</key>
			<string>/var/run/lunepack-org.example.hello.sock</string>
			<key>SockPathMode</key>
			<integer>438</integer>
		</dict>
	</dict>
</dict>
</plist>
```

The block is the plist without a bundle identifier; the test in `crates/lunepack-os-macos/tests/format_doc.rs`
checks it equals the bytes the registrar writes. The service updates its own binary as in 20.4 and 18.3.

The bundle, its pointer, its identity, the swap slots and the reconcile are those of 17, run by the engine as
root with `R` in the machine home; the engine, not the app, owns `B` (root-owned, in `/Applications`), and a
user's app that finds itself in such a bundle is a machine install by 20.1, never an adoption (17.5) or a
per-user update.

The first install is a signed installer package (CLI.md, `setup`): Installer places the runtime and the
payload file of 14.4 below `/Library/Application Support/lunepack/.installer/<app id>/`, in folders that
only root can read or change, and runs the package's one `postinstall` line, `machine-install --pkg`. The
mode takes no argument and no environment variable; it requires its own image and the payload to stand in
admin-only folders of that path before it reads either, copies the payload into
`.lunepack-install-<32 hex>`, verifies the copy under the trailer's root (there is no separate anchor,
THREAT-MODEL), and then installs through the engine; the same version found installed is repaired, another
is `already_installed`.

### 20.6 Policy files

An administrator's policy for an app is a JSON file, read and never written by lunepack:
`/etc/lunepack/policy/<app id>.json` on Linux and `/Library/Application Support/lunepack/.policy/<app id>.json`
on macOS. It is one strict-JSON object (3.1: duplicate keys refused) of at most 4096 bytes with two optional
members, the booleans `disable_self_update` and `no_update_ui`, which mean what `DisableSelfUpdate` and
`NoUpdateUi` mean in 18.4. No file at that name: both off. A file that is there but not a regular file (a link,
FIFO, device or directory), not owned by uid 0, writable by its group or by others, in a directory that is
not a real directory owned by uid 0 or is writable by its group or by others, larger than 4096 bytes, not
strict JSON, holding an unknown member or a value that is not a boolean: **both on**, so a damaged policy
errs toward no update (M10-D12). The file is opened without following a link and judged through the
descriptor it opened.

### 20.7 The per-user home

Each user of a per-machine install keeps what the library needs in `<data home>/.lunepack/<app id>/`, with
the data home `$XDG_DATA_HOME` (else `~/.local/share`) on Linux and `~/Library/Application Support` on
macOS:

| Path | Holds |
|---|---|
| `state/` | this user's lock, and `state/<install_id as 32 hex>/` with the `install-counters` records (12.6) |
| `cache/` | the download cache |
| `logs/` | the library's and the runtime's log for this user |

No app id starts with `.`, so this never meets a per-user install's `R = <data home>/<app id>`. The location is
a **cross-version contract** as 18.5 is: every later library version must find the counters (12.6, including
`last_run`, 12.9) there. Another user's home is never read or written, and an uninstall removes only the
uninstalling user's.

### 20.8 Integration

The engine writes, as root, the integration the per-user rules of 12.7 and 17.6 describe, to the system-wide
places and under the same marker rules (an entry that is not lunepack's is never replaced and is reported):

- Linux: the desktop entry `/usr/local/share/applications/<app id>.desktop`, the command link
  `/usr/local/bin/<bin>` and, when the app declares autostart, `/etc/xdg/autostart/<app id>.desktop`, each
  going through `R/current`. The package manager's `/usr/share` and `/usr/bin` are never touched.
- macOS: when the app declares autostart, the LaunchAgent `/Library/LaunchAgents/lunepack-<app id>.autostart.plist`
  (label `lunepack-<app id>.autostart`, root:wheel, mode 0644; the program is the entry inside the live bundle),
  which runs in each user's session at the next sign-in and is never loaded with `launchctl`. There is no
  shortcut: the bundle in `/Applications` is the entry.

### 20.9 Names

The names of 20.1 and 20.3 to 20.5 for the example app id `org.example.hello` and the version `1.2.3`, one
`<name> | <value>` per line, generated by the core's own functions. A test (`format_doc` of `lunepack-core`)
checks that this block equals what they return, line for line.

```text unix-names
app id | org.example.hello
version | 1.2.3
linux machine home | /opt
linux install root R | /opt/org.example.hello
linux versions | /opt/org.example.hello/app
linux version tree | /opt/org.example.hello/app/1.2.3
linux state | /opt/org.example.hello/.lunepack/state
linux logs | /opt/org.example.hello/.lunepack/logs
linux lock | /opt/org.example.hello/.lunepack/machine/lock
linux incoming | /opt/org.example.hello/.lunepack/machine/incoming
linux service binary | /opt/org.example.hello/.lunepack/machine/service/1.2.3/lunepack-service
linux stable service link | /opt/org.example.hello/.lunepack/machine/lunepack-service
linux per-user home | <data home>/.lunepack/org.example.hello
linux socket directory | /run/lunepack
linux socket | /run/lunepack/org.example.hello.sock
linux longest socket path | 107
macos machine home | /Library/Application Support/lunepack
macos install root R | /Library/Application Support/lunepack/org.example.hello
macos versions | /Library/Application Support/lunepack/org.example.hello/app
macos version tree | /Library/Application Support/lunepack/org.example.hello/app/1.2.3
macos state | /Library/Application Support/lunepack/org.example.hello/.lunepack/state
macos logs | /Library/Application Support/lunepack/org.example.hello/.lunepack/logs
macos lock | /Library/Application Support/lunepack/org.example.hello/.lunepack/machine/lock
macos incoming | /Library/Application Support/lunepack/org.example.hello/.lunepack/machine/incoming
macos service binary | /Library/Application Support/lunepack/org.example.hello/.lunepack/machine/service/1.2.3/lunepack-service
macos stable service link | /Library/Application Support/lunepack/org.example.hello/.lunepack/machine/lunepack-service
macos per-user home | <data home>/.lunepack/org.example.hello
macos socket directory | /var/run
macos socket | /var/run/lunepack-org.example.hello.sock
macos longest socket path | 103
linux projection target | app/1.2.3
linux socket unit | lunepack-org.example.hello.socket
linux service unit | lunepack-org.example.hello.service
linux unit directory | /etc/systemd/system
macos label | lunepack-org.example.hello
macos plist | /Library/LaunchDaemons/lunepack-org.example.hello.plist
macos launchd socket name | lunepack
service file (unix) | lunepack-service
```

## 21. Prebuilt binary list

lunepack's own releases publish the binaries a packager places into an app (the runtime, the UI, the
update service and the Windows stubs) as prebuilt files, with one signed list of them per lunepack
version: `prebuilt-<version>.sig.json`, an envelope (section 2) of kind `prebuilt`, payload type
`application/vnd.lunepack.prebuilt.v1+json`. `<version>` is the payload's `version`. No app reader
opens this kind; it is read by lunepack's own CLI and by anyone checking a download of those
binaries.

```json prebuilt
{
  "format": 1,
  "kind": "prebuilt",
  "critical": [],
  "version": "0.1.0",
  "source_commit": "11bc638e35a0c6311d423720574aa450b719ef56",
  "rehearsal": false,
  "binaries": [
    {
      "kind": "runtime",
      "target": "linux-x86_64",
      "size": 4718592,
      "sha256": "afafc6d6a7cb1369abfed59823c755f1738b02ad5b6257108236f86b4bbb34c1"
    },
    {
      "kind": "ui",
      "target": "linux-x86_64",
      "size": 13631488,
      "sha256": "4ac1684c1f6a38c745bd4bd5d533e79fac0c0183ef854dbbb209bb0f6d17eb46"
    },
    {
      "kind": "service",
      "target": "linux-x86_64",
      "size": 3145728,
      "sha256": "5a2368f9431046dbd07bbfb92cd6314954f3133f506932903db76e48d0b63495"
    }
  ]
}
```

| Field | Rule |
|---|---|
| `version` | the lunepack version the binaries belong to: a version (10.3) |
| `source_commit` | the git commit the binaries were built from: exactly 40 lowercase hex characters |
| `rehearsal` | REQUIRED boolean; `true` marks a list made by a release rehearsal. Any other value, and a missing member, MUST be rejected |
| `binaries` | 1 to 64 rows (section 4) |
| `binaries[].kind` | one of `runtime`, `ui`, `service`, `stub`, `stub-console` |
| `binaries[].target` | a target id (10.4) |
| `binaries[].size` | integer ≥ 1: the file's length in bytes |
| `binaries[].sha256` | digest (3.2) of the file's bytes |

- No two rows have the same `kind` and `target`. With five kinds and seven target ids, a v1 list
  has at most 35 rows; the cap of 64 bounds the work before that rule runs.
- Unknown members are ignored, at the top level and in rows, as for every payload (3.2).
- The envelope is signed by the threshold (2.6) of a key set that the verifier already holds: 1 to
  16 Ed25519 keys (2.5), no key twice, with a threshold `1 ≤ threshold ≤ keys`, as a root's
  (5.1). lunepack's own CLI has the project's key set compiled in. No root document and no rotation
  document of section 5 exists for this kind, and it is not signed by release keys (section 6).
- The signature has no validity period: a reader checks no time, expiry or anti-rollback floor
  for this kind.
- A reader that also holds the list as a separate file (the payload alone) MUST compare it byte
  for byte with the decoded payload of the envelope and use it only when they are equal. The
  separate file is capped like the document (section 4).
- A list whose `rehearsal` is `true` MUST NOT make a reader accept a binary. It exists so a release
  rehearsal signs with the real key while leaving nothing that can pass for a release.
