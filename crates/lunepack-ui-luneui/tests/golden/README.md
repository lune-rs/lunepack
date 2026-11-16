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

| set | made by | compared by | class |
|---|---|---|---|
| `linux/` | the reference image (below) | the reference image: `scripts/ui-golden.sh --docker`, and the CI leg `linux-golden` | `exact` |
| `macos/` | the CI leg `macos` (Metal) | the CI leg `macos`, and a developer's Mac | `cross` |
| `windows/` | the CI leg `windows` (WARP) | the CI leg `windows` | `cross` |

`linux/` is committed. `macos/` and `windows/` do not exist until they are seeded from the frames CI
uploads (below). Until one exists, that OS's golden run fails with "no golden set for `<os>`; seed it
from the frames ..." after rendering every frame and saving it, so CI has the frames to upload; it
never skips and never compares against another OS's set. The plain `cargo test` still passes on every
OS: it checks the Linux set and any other set that exists (a half seeded set, or one with a file no
scene names, fails it).

## Reference image (the Linux set)

The Linux set is generated and compared in one pinned image, `scripts/ui-golden.Dockerfile`: the
gate's base image plus `mesa-vulkan-drivers`.

- Mesa (lavapipe): `25.0.7-2+deb13u1` (`dpkg-query` in the image; every run of `scripts/ui-golden.sh`
  prints it).
- Rewrite it (only ever from that image): `scripts/ui-golden.sh --docker --write`.
- Compare: `scripts/ui-golden.sh --docker` (the same image on any machine).

## Seeding and refreshing the macOS and Windows sets

The renders of a golden run are left in `target/ui-golden-out` (`LUNEPACK_GOLDEN_OUT`), and the CI job
`ui` uploads them as the artifacts `ui-golden-renders-macos` and `ui-golden-renders-windows`, whether
the run passed or not. To seed a set, or to refresh it after a screen changed on purpose:

1. Find the run of the job `ui` on the commit that should become the reference, and download the
   artifact of the OS: `gh run download <run id> -n ui-golden-renders-<macos|windows> -D <scratch dir>`.
2. Replace the set with the frames: remove `tests/golden/<os>/*.png`, create the directory if need be
   and copy the artifact's `*.png` into it. The artifact holds exactly the 88 frames and nothing else.
3. Run `cargo test -p lunepack-ui-luneui --locked --test golden` (the plain test checks the names), look
   at the frames that changed, and commit the set.

A set must come from CI's own adapter, not from a developer's machine: the point of a per-OS set is
that CI compares with what CI renders. A refresh is a review of the frames, never a way to make a
failing comparison pass without looking at it.

## Tolerance

Per adapter class, constants in `tests/golden.rs` with their measurements (the step 0 probe in the
task notes, "M6 step 0"):

| class | where | max channel delta | pixels differing |
|---|---|---|---|
| `exact` | the reference image | 0 | 0 |
| `cross` | Metal, WARP | 6 | at most 10 % |

The class is `LUNEPACK_GOLDEN_CLASS` (`exact` or `cross`; the scripts and CI set it). A failure prints
both numbers. The `cross` bound now covers the drift between two machines that run the same adapter
(a developer's Mac against a CI runner); it is not the distance between adapters, which is why the
sets are per OS. It is never loosened to make a run pass.

`cargo test` without `--ignored` also checks the comparison itself on known cases: identical images
give 0 and 0, and one pixel changed by 40 gives 40 and 1.
