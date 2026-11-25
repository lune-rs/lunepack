# Security policy

lunepack installs and updates other people's programs, so a flaw in it can put code on a user's machine.
This page says how to report one, what counts, and how to check that the prebuilt binaries you
download are the project's.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: on the repository's page, open the Security tab and choose
"Report a vulnerability" (`https://github.com/lune-rs/lunepack/security/advisories/new`). That opens a
private advisory that only you and the maintainers can read. Please do not open a public issue or pull
request for a vulnerability, and do not post exploit details anywhere public before a fix is released.

Say what you found, how to reproduce it (a failing input, a command, a small repository), which version
or commit you used, and what you think an attacker gains. A report that is not a vulnerability is still
welcome as an ordinary issue.

## What is in scope

- The packager and the documents it writes, and the code that verifies them: `lunepack` (the command
  line), the format ([`docs/FORMAT.md`](docs/FORMAT.md)) and the verification order of a client.
- The code that runs on a user's machine: the facade crate `lunepack`, `lunepack-runtime`, the installer
  and update window (`lunepack-ui`), the Windows launcher stub, and the update service of an install for
  all users.
- The release machinery of this repository: the release workflow, `scripts/release/`, the prebuilt
  binaries' list and its signature, and the project key's use (below).
- The libraries under the crates of the `lunepack` family that are published to crates.io.

What lunepack does and does not defend against is written down in the
[threat model](docs/THREAT-MODEL.md); something that the threat model lists as "not stopped" (a malicious
publisher, a process running as the same user as the app) is a known limit, not a vulnerability, though a
way to make it worse than the threat model says is one.

A flaw in a program that an app packs with lunepack is the app's, not lunepack's. A flaw in a dependency
belongs to its own project; tell us when lunepack's use of it is what makes it exploitable.

## Checking a download of the prebuilt binaries

A release of lunepack carries the files a packager places into an app (the runtime, the window program,
the update service and the Windows stubs, for six target ids) and, beside them, one signed list of them:
`prebuilt-<version>.json` (the list) and `prebuilt-<version>.sig.json` (its signature). The `lunepack`
command line of that version pins the same list in its own source, so
`lunepack prebuilt fetch --target <target> --out <dir>` checks every file against it before it places it
([`docs/CLI.md`](docs/CLI.md), "`lunepack prebuilt fetch`"). To check files you downloaded by another way:

```
lunepack prebuilt verify --list prebuilt-<version>.json --sig prebuilt-<version>.sig.json --dir <downloads>
```

(with `--all` when every row's file must be there). Use a `lunepack` that you obtained before that
release, or from crates.io (`cargo install lunepack-cli --locked`), not the one downloaded together with
the files: a check made by a program that came from the same place as the files proves nothing about that
place. A CLI compiled before a key rotation checks a later release only with `--trusted-key <public key>`
(and `--threshold <n>` for a set of several), taking the key from the table below or from the source of a
newer release.

What a pass proves: the holders of the project's key signed this list, so a run of the project's release
workflow on `main` that its maintainer approved made it, and every file you checked has the size and
SHA-256 of a row. What it does not prove: how those files were built (there is no build attestation of any
kind) or that the source is free of flaws. The `lunepack` command line itself, downloaded from the release
page, carries no proof at all: it is built at the release tag, after the one signing, and nothing signs it.
If that matters to you, build it from the tag or install it with `cargo install lunepack-cli --locked`.
The threat model, section "lunepack's own supply chain", says who can use the key and what a theft of it
allows.

## The project's key sets

No project key has been published yet.

When one is, this section lists every key set that has been built into the `lunepack` command line, oldest
first, in a table with one row per key: the set's version, its threshold, the public key and its key id (the
SHA-256 of the public key, as `lunepack keys show` prints it), and whether the set is `current` or
`retired`. A retired set never pins a binary; it only checks the list of an older release (`prebuilt
verify --root-version <n>`). The table is held equal to what the built CLI reports by
`scripts/tests/test-project-key-docs.sh`, so a key that is in the source and not here, or here and not in
the source, fails the repository's tests. How a key is made, kept and replaced is in
[`docs/RELEASING.md`](docs/RELEASING.md).
