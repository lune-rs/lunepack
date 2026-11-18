# Golden frames of the UI screens (M6-D9)

Every screen of the install, update and uninstall flows, and every transition between them, rendered
headless at scale 1.0 and at fixed times by `tests/golden.rs`. Opaque material, Linux wording, the
generated sample icon (`scenario::sample_icon_png`). A name is `<scene>.png` for a settled screen and
`<transition>-<tier>-t<ms>.png` for a frame of a strip, `<ms>` counted from the instant of the change.

## One set per OS

Each OS compares against its own set of the same 88 frames, because the adapters do not agree: the
frames of Metal differ from the ones of lavapipe by at most 3 per channel, but in 11 of the 88 frames
(the transition strips, where glow, blur and fades are on screen) on 10.35 to 23.94 % of the
pixels, over the 10 % the cross-adapter bound allows. The bound was not loosened; the sets were split.

| set | made and checked on | how | class |
|---|---|---|---|
| `linux-aarch64/` | an arm64 machine with Docker (a Mac, say) | `scripts/ui-golden.sh --docker` (reference image, below) | `exact` |
| `linux-x86_64/` | an x86-64 Linux machine with Docker | `scripts/ui-golden.sh --docker` (reference image, below) | `exact` |
| `macos/` | a Mac, natively (Metal) | `scripts/ui-golden.sh` | `cross` |
| `windows/` | a Windows machine, natively (WARP or a hardware adapter) | `LUNEPACK_GOLDEN_CLASS=cross cargo test -p lunepack-ui-luneui --locked --test golden -- --ignored` | `cross` |

The pixel gate is local (M6-D13): CI does not render or compare these frames. Each set is checked on its
own machine class in every step that changes how a screen looks, and before every push that touches
`crates/lunepack-ui*` or `scripts/ui-golden*`. A set is re-seeded only on the machine class that checks
it, and a mismatch is never answered with a looser tolerance.

The Linux set is split by CPU because lavapipe renders arm64 and x86-64 slightly differently (a channel
delta of 2 on 0.14 to 0.37 % of the pixels in 82 of the 88 frames; repeats on one CPU are
byte-identical). Same-image Linux stays `exact` against the set of its own CPU. A Linux CPU with
neither set fails closed like an OS with none.

All four sets are committed. A golden run on an OS with no set fails with "no golden set for `<os>`; seed
it ..." after rendering every frame and saving it under `target/ui-golden-out`; it never skips and never
compares against another OS's set. The plain `cargo test` still passes on every OS: it checks the sets
that exist (a half seeded set, or one with a file no scene names, fails it).

## Reference image (the Linux sets)

The Linux sets are generated and compared in one pinned image, `scripts/ui-golden.Dockerfile`: the
gate's base image plus `mesa-vulkan-drivers`.

- Mesa (lavapipe): `25.0.7-2+deb13u1` (`dpkg-query` in the image; every run of `scripts/ui-golden.sh`
  prints it).
- Rewrite the set of the CPU Docker runs the image on (only ever from that image):
  `scripts/ui-golden.sh --docker --write` (`linux-aarch64` on an arm64 machine, `linux-x86_64` on an
  x86-64 host).
- Compare: `scripts/ui-golden.sh --docker` (the same image, against the set of its CPU).

## Seeding and refreshing a set

Re-seed on the set's own machine class, then look at what changed:

1. Linux: `scripts/ui-golden.sh --docker --write`. macOS and Windows: run the comparison command in the
   table with `LUNEPACK_WRITE_GOLDENS=1` added (the golden test then writes the set instead of
   comparing).
2. `git status` and `git diff --stat crates/lunepack-ui-luneui/tests/golden`: only the frames of the
   screen that changed on purpose may differ. A set holds exactly the 88 frames and nothing else.
3. Run `cargo test -p lunepack-ui-luneui --locked --test golden` (the plain test checks the names), look
   at the frames that changed, and commit the set.

A refresh is a review of the frames, never a way to make a failing comparison pass without looking at it.

## Tolerance

Per adapter class, constants in `tests/golden.rs` with their measurements (the step 0 probe in the
task notes, "M6 step 0"):

| class | where | max channel delta | pixels differing |
|---|---|---|---|
| `exact` | the reference image | 0 | 0 |
| `cross` | Metal, WARP | 6 | at most 10 % |

The class is `LUNEPACK_GOLDEN_CLASS` (`exact` or `cross`; `scripts/ui-golden.sh` sets it). A failure prints
both numbers. The `cross` bound now covers the drift between two machines that run the same adapter
(two machines of one class); it is not the distance between adapters, which is why the
sets are per OS. It is never loosened to make a run pass.

`cargo test` without `--ignored` also checks the comparison itself on known cases: identical images
give 0 and 0, and one pixel changed by 40 gives 40 and 1.
