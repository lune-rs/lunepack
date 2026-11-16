# Golden frames of the UI screens (M6-D9)

Every screen of the install, update and uninstall flows, and every transition between them, rendered
headless at scale 1.0 and at fixed times by `tests/golden.rs`. Opaque material, Linux wording, the
generated sample icon (`scenario::sample_icon_png`). A name is `<scene>.png` for a settled screen and
`<transition>-<tier>-t<ms>.png` for a frame of a strip, `<ms>` counted from the instant of the change.

## Reference

The goldens are generated and compared in one pinned image, `scripts/ui-golden.Dockerfile`: the gate's
base image plus `mesa-vulkan-drivers`.

- Mesa (lavapipe): `25.0.7-2+deb13u1` (`dpkg-query` in the image; every run of `scripts/ui-golden.sh`
  prints it).
- Rewrite them (only ever from that image): `scripts/ui-golden.sh --docker --write`.
- Compare: `scripts/ui-golden.sh --docker` (the same image on any machine), or natively on macOS with
  `scripts/ui-golden.sh` (Metal). The CI job `ui` runs both and the other OSes natively.

## Tolerance

Per adapter class, constants in `tests/golden.rs` with their measurements (the step 0 probe in the
task notes, "M6 step 0"):

| class | where | max channel delta | pixels differing |
|---|---|---|---|
| `exact` | the reference image | 0 | 0 |
| `cross` | Metal, WARP | 6 | at most 10 % |

The class is `LUNEPACK_GOLDEN_CLASS` (`exact` or `cross`; the scripts and CI set it). A failure prints
both numbers. The renders of every run are left in `target/ui-golden-out` (`LUNEPACK_GOLDEN_OUT`).

`cargo test` without `--ignored` checks that a golden exists for every screen the reducer can reach,
that no golden is unnamed by a scene, and the comparison itself on known cases.
