//! Golden frames (M6-D9): every screen and every transition of the three flows, rendered headless at
//! scale 1.0 and fixed times, compared with the PNGs of the golden set of the OS (and, on Linux, the
//! CPU) the test runs on: `tests/golden/linux-aarch64` and `tests/golden/linux-x86_64` (made in the
//! reference Docker image on that CPU), `tests/golden/macos` (Metal) and `tests/golden/windows`
//! (WARP). Each OS compares against its own adapter, because a frame from another adapter differs on
//! 10 to 24 % of the pixels in the transition strips, and lavapipe on arm64 differs from lavapipe on
//! x86_64 by a channel delta of 2 on 0.14 to 0.37 % of the pixels (see the README).
//!
//! The comparison needs a GPU adapter, so it is `#[ignore]`d and run with `--ignored` by
//! `scripts/ui-golden.sh` and the CI job `ui`; with no adapter it fails, it never skips. With no
//! golden set for the OS it renders everything (so CI can upload the frames) and then fails, saying
//! how to seed the set. A Linux set is generated in the reference image only
//! (`scripts/ui-golden.sh --docker --write`, which sets `LUNEPACK_WRITE_GOLDENS=1`, the same
//! convention as the fuzz seeds, on a machine of that CPU), or seeded from the frames CI uploads; the
//! other two come from the frames CI uploads (README). A Linux CPU with no set fails closed like an OS
//! with none. A plain `cargo test --workspace` stays adapter-free: it runs the checks that need no
//! GPU (the comparison instrument, and that both Linux sets hold a golden for every screen the
//! reducer can reach and for nothing else).
//!
//! Tolerance is per adapter class, chosen by `LUNEPACK_GOLDEN_CLASS` (`exact` or `cross`; the
//! scripts and CI set it, the default is `cross`). The numbers come from the step 0 probe (notes.md
//! "M6 step 0", items (iii) and (iv)).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use lune_ui::motion::MotionTier;

use lunepack_core::ui::{Flow, Screen};
use lunepack_ui_luneui::render::{Player, RenderOptions, Renderer, RgbaImage, Timed};
use lunepack_ui_luneui::{Env, Material, Os, icon, scenario};

/// Same-image Linux (lavapipe in `scripts/ui-golden.Dockerfile`): exact, against the set of the same
/// CPU. Measured (notes.md "M6 step 0" (iii)): repeated renders are byte-identical. arm64 does not
/// equal amd64 (CI, run 44164339009: channel delta 2 on 0.14 to 0.37 % of the pixels), which is why
/// the Linux set is split by CPU.
const EXACT_MAX_DELTA: u8 = 0;
const EXACT_MAX_FRACTION: f64 = 0.0;
/// Cross-adapter (Metal, WARP): at most this channel delta, on at most this fraction of the pixels
/// differing at all. Measured Metal against lavapipe (notes.md "M6 step 0" (iv)): delta 2 and 3.94 %.
/// With the real screens the same comparison reached 10.35 to 23.94 % in 11 of the 88 frames, so the
/// bound was kept and the sets made per OS (README): it now allows the drift between two machines
/// that run the same adapter (a developer's Mac and a CI runner), never a different adapter.
const CROSS_MAX_DELTA: u8 = 6;
const CROSS_MAX_FRACTION: f64 = 0.10;

/// The adapter class a run compares in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Exact,
    Cross,
}

impl Class {
    fn from_env() -> Class {
        match std::env::var("LUNEPACK_GOLDEN_CLASS").as_deref() {
            Ok("exact") => Class::Exact,
            Ok("cross") | Err(_) => Class::Cross,
            Ok(other) => panic!("LUNEPACK_GOLDEN_CLASS must be `exact` or `cross`, not `{other}`"),
        }
    }

    fn limits(self) -> (u8, f64) {
        match self {
            Class::Exact => (EXACT_MAX_DELTA, EXACT_MAX_FRACTION),
            Class::Cross => (CROSS_MAX_DELTA, CROSS_MAX_FRACTION),
        }
    }
}

/// How two images differ.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Diff {
    /// The largest difference of any channel of any pixel.
    max_delta: u8,
    /// Pixels that differ in any channel.
    differing: usize,
    /// All pixels.
    total: usize,
}

impl Diff {
    fn fraction(&self) -> f64 {
        self.differing as f64 / self.total.max(1) as f64
    }

    fn within(&self, class: Class) -> bool {
        let (delta, fraction) = class.limits();
        self.max_delta <= delta && self.fraction() <= fraction
    }
}

/// Compares two RGBA buffers of equal size (a size mismatch is a difference everywhere).
fn diff(a: &[u8], b: &[u8]) -> Diff {
    if a.len() != b.len() {
        return Diff {
            max_delta: 255,
            differing: a.len().max(b.len()) / 4,
            total: a.len().max(b.len()) / 4,
        };
    }
    let mut max_delta = 0u8;
    let mut differing = 0usize;
    for (x, y) in a.as_chunks::<4>().0.iter().zip(b.as_chunks::<4>().0) {
        let d = (0..4).map(|i| x[i].abs_diff(y[i])).max().unwrap_or(0);
        if d > 0 {
            differing += 1;
            max_delta = max_delta.max(d);
        }
    }
    Diff {
        max_delta,
        differing,
        total: a.len() / 4,
    }
}

/// One scripted scene: the frames to capture and their names.
struct Scene {
    flow: Flow,
    tier: MotionTier,
    script: Vec<Timed>,
    /// `(file stem, time in ms)`.
    shots: Vec<(String, u64)>,
}

const OS: Os = Os::Linux;
const LONG_NAME: &str = "Lunegit Professional Edition for Very Large Repositories and Monorepos";

/// The frame times of a transition's strip, from the instant of the change.
const STRIP_FULL: [u64; 4] = [0, 120, 240, 430];
const STRIP_REDUCED: [u64; 2] = [120, 300];

fn scenes() -> Vec<Scene> {
    let mut out = Vec::new();
    let mut still = |name: &str, flow: Flow, script: Vec<Timed>, at: u64| {
        out.push(Scene {
            flow,
            tier: MotionTier::Full,
            script,
            shots: vec![(name.to_owned(), at)],
        });
    };
    // Every screen, settled.
    still(
        "install-welcome",
        Flow::Install,
        scenario::install_welcome(OS, scenario::APP_NAME, true),
        600,
    );
    still(
        "install-welcome-long-name",
        Flow::Install,
        scenario::install_welcome(OS, LONG_NAME, false),
        600,
    );
    still(
        "install-installing",
        Flow::Install,
        scenario::install_running(OS, 1000),
        3000,
    );
    still(
        "install-done",
        Flow::Install,
        scenario::install_done(OS, 1000, 4000),
        5500,
    );
    still(
        "install-failed",
        Flow::Install,
        scenario::install_failed(OS, 1000, 4000, 9),
        5500,
    );
    still(
        "update-waiting",
        Flow::Update,
        scenario::update_waiting(),
        1000,
    );
    still(
        "update-applying",
        Flow::Update,
        scenario::update_applying(1000, 74),
        2500,
    );
    still(
        "update-starting",
        Flow::Update,
        scenario::update_starting(1000, 2000),
        3500,
    );
    still(
        "update-rolled-back",
        Flow::Update,
        scenario::update_rolled_back(1000, 2000, 3000),
        4500,
    );
    still(
        "update-failed",
        Flow::Update,
        scenario::update_failed(1000, 3000, 9),
        4500,
    );
    still(
        "uninstall-confirm",
        Flow::Uninstall,
        scenario::uninstall_confirm(OS),
        600,
    );
    still(
        "uninstall-removing",
        Flow::Uninstall,
        scenario::uninstall_removing(OS, 1000),
        3000,
    );
    for (name, n) in [("none", 0), ("one", 1), ("many", 6)] {
        still(
            &format!("uninstall-done-{name}"),
            Flow::Uninstall,
            scenario::uninstall_done(OS, 1000, 4000, scenario::leftovers(OS, n)),
            5500,
        );
    }
    still(
        "uninstall-failed",
        Flow::Uninstall,
        scenario::uninstall_failed(OS, 1000, 4000, 9),
        5500,
    );

    // Every transition, in both tiers.
    let mut strip = |name: &str, flow: Flow, script: Vec<Timed>, base: u64| {
        for (tier, label, times) in [
            (MotionTier::Full, "full", &STRIP_FULL[..]),
            (MotionTier::Reduced, "reduced", &STRIP_REDUCED[..]),
        ] {
            out.push(Scene {
                flow,
                tier,
                script: script.clone(),
                shots: times
                    .iter()
                    .map(|t| (format!("{name}-{label}-t{t:04}"), base + t))
                    .collect(),
            });
        }
    };
    strip(
        "install-welcome-to-installing",
        Flow::Install,
        scenario::install_running(OS, 1000),
        1000,
    );
    strip(
        "install-installing-to-done",
        Flow::Install,
        scenario::install_done(OS, 1000, 4000),
        4000,
    );
    strip(
        "install-installing-to-failed",
        Flow::Install,
        scenario::install_failed(OS, 1000, 4000, 9),
        4000,
    );
    strip(
        "install-window-in",
        Flow::Install,
        scenario::install_welcome(OS, scenario::APP_NAME, true),
        0,
    );
    strip(
        "update-waiting-to-applying",
        Flow::Update,
        scenario::update_applying(1000, 74),
        1000,
    );
    strip(
        "update-applying-to-starting",
        Flow::Update,
        scenario::update_starting(1000, 2500),
        2500,
    );
    strip(
        "update-starting-to-rolled-back",
        Flow::Update,
        scenario::update_rolled_back(1000, 2000, 4000),
        4000,
    );
    strip(
        "update-starting-to-updated",
        Flow::Update,
        scenario::update_updated(1000, 2000, 4000),
        4000,
    );
    strip(
        "update-window-in",
        Flow::Update,
        scenario::update_waiting(),
        0,
    );
    strip(
        "uninstall-confirm-to-removing",
        Flow::Uninstall,
        scenario::uninstall_removing(OS, 1000),
        1000,
    );
    strip(
        "uninstall-removing-to-done",
        Flow::Uninstall,
        scenario::uninstall_done(OS, 1000, 4000, scenario::leftovers(OS, 1)),
        4000,
    );
    strip(
        "uninstall-removing-to-failed",
        Flow::Uninstall,
        scenario::uninstall_failed(OS, 1000, 4000, 9),
        4000,
    );
    out
}

fn options(scene: &Scene) -> RenderOptions {
    RenderOptions {
        env: Env {
            os: OS,
            material: Material::Opaque,
        },
        tier: scene.tier,
        scale: 1.0,
        flow: scene.flow,
    }
}

/// The golden set of the OS (and, on Linux, the CPU) this test runs on. A Linux CPU with no set
/// here is `linux-unsupported`, which never exists, so its golden run fails closed.
const SET: &str = if cfg!(target_os = "macos") {
    "macos"
} else if cfg!(windows) {
    "windows"
} else if cfg!(target_arch = "aarch64") {
    "linux-aarch64"
} else if cfg!(target_arch = "x86_64") {
    "linux-x86_64"
} else {
    "linux-unsupported"
};

/// The sets a golden directory can hold: one per OS, and two on Linux (one per CPU).
const SETS: [&str; 4] = ["linux-aarch64", "linux-x86_64", "macos", "windows"];

/// The Linux sets: the reference ones, always there.
const LINUX_SETS: [&str; 2] = ["linux-aarch64", "linux-x86_64"];

fn golden_set_dir(set: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(set)
}

fn golden_dir() -> PathBuf {
    golden_set_dir(SET)
}

/// The PNG file names of a set on disk; empty when the set does not exist.
fn names_on_disk(set: &str) -> BTreeSet<String> {
    std::fs::read_dir(golden_set_dir(set))
        .map(|dir| {
            dir.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".png"))
                .collect()
        })
        .unwrap_or_default()
}

fn out_dir() -> PathBuf {
    std::env::var_os("LUNEPACK_GOLDEN_OUT").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-golden-out"),
        PathBuf::from,
    )
}

/// Every golden file name the scenes name.
fn expected_names() -> BTreeSet<String> {
    scenes()
        .iter()
        .flat_map(|s| s.shots.iter().map(|(n, _)| format!("{n}.png")))
        .collect()
}

/// The screen a scene's last frame shows, from the reducer alone: its script up to that time is
/// played into the model, with no frame and no GPU.
fn final_screen(scene: &Scene) -> Screen {
    let mut player = Player::new(options(scene));
    let last = scene.shots.iter().map(|(_, t)| *t).max().unwrap_or(0);
    for item in scene
        .script
        .iter()
        .filter(|s| s.at <= Duration::from_millis(last))
    {
        player.play(item).expect("the scene's script is valid");
    }
    player.model.screen()
}

/// Whether a golden is required for `screen`: every screen the reducer can reach. The match has no
/// wildcard, so a new screen fails to compile here until it is decided.
fn reachable(screen: Screen) -> bool {
    match screen {
        Screen::Idle | Screen::Closed => false,
        Screen::InstallWelcome
        | Screen::Installing
        | Screen::InstallDone
        | Screen::InstallFailed
        | Screen::UpdateWaiting
        | Screen::UpdateApplying
        | Screen::UpdateStarting
        | Screen::UpdateRolledBack
        | Screen::UpdateFailed
        | Screen::UninstallConfirm
        | Screen::Uninstalling
        | Screen::UninstallDone
        | Screen::UninstallFailed => true,
    }
}

/// Every screen the reducer can reach, listed once.
const ALL_SCREENS: [Screen; 15] = [
    Screen::Idle,
    Screen::InstallWelcome,
    Screen::Installing,
    Screen::InstallDone,
    Screen::InstallFailed,
    Screen::UpdateWaiting,
    Screen::UpdateApplying,
    Screen::UpdateStarting,
    Screen::UpdateRolledBack,
    Screen::UpdateFailed,
    Screen::UninstallConfirm,
    Screen::Uninstalling,
    Screen::UninstallDone,
    Screen::UninstallFailed,
    Screen::Closed,
];

#[test]
fn the_comparison_instrument_is_right_on_known_cases() {
    let a = vec![10u8; 4 * 100];
    assert_eq!(
        diff(&a, &a),
        Diff {
            max_delta: 0,
            differing: 0,
            total: 100
        }
    );
    let mut b = a.clone();
    b[4 * 37 + 1] += 40;
    assert_eq!(
        diff(&a, &b),
        Diff {
            max_delta: 40,
            differing: 1,
            total: 100
        }
    );
    // The classes: exact allows nothing, cross allows delta 6 on 10 % of the pixels.
    assert!(diff(&a, &a).within(Class::Exact));
    assert!(!diff(&a, &b).within(Class::Exact));
    assert!(
        !diff(&a, &b).within(Class::Cross),
        "a delta of 40 is over the cross bound"
    );
    let mut c = a.clone();
    for px in c.as_chunks_mut::<4>().0.iter_mut().take(10) {
        px[0] += 6;
    }
    assert!(
        diff(&a, &c).within(Class::Cross),
        "delta 6 on 10 % is the bound"
    );
    for px in c.as_chunks_mut::<4>().0.iter_mut().take(11) {
        px[0] = 16;
    }
    assert!(
        !diff(&a, &c).within(Class::Cross),
        "11 % differing is over the bound"
    );
    let mut d = a.clone();
    d[0] += 7;
    assert!(
        !diff(&a, &d).within(Class::Cross),
        "delta 7 is over the bound"
    );
    assert_eq!(
        diff(&a, &a[..8]).max_delta,
        255,
        "sizes that differ never match"
    );
}

#[test]
fn every_screen_the_reducer_can_reach_has_a_golden_and_nothing_else_does() {
    // The still scenes end on each screen; the strips add transitions.
    let mut covered = BTreeSet::new();
    // The stills (one frame each) end on the screens; the strips only add transitions.
    for scene in scenes().into_iter().filter(|s| s.shots.len() == 1) {
        let screen = final_screen(&scene);
        covered.insert(format!("{screen:?}"));
    }
    for screen in ALL_SCREENS {
        if reachable(screen) {
            assert!(
                covered.contains(&format!("{screen:?}")),
                "no scene ends on {screen:?}: add its golden"
            );
        }
    }
    let expected = expected_names();
    // The Linux sets are the reference and always there. A set of another OS is checked when it has
    // been seeded; a half seeded one (or one with a stale file) fails here, so the plain test run
    // of every OS notices it. A set that does not exist yet is the ignored test's to refuse.
    for set in LINUX_SETS {
        assert!(
            !names_on_disk(set).is_empty(),
            "the Linux golden set (tests/golden/{set}) is missing"
        );
    }
    for set in SETS {
        let on_disk = names_on_disk(set);
        if on_disk.is_empty() {
            continue;
        }
        let missing: Vec<_> = expected.difference(&on_disk).collect();
        let stale: Vec<_> = on_disk.difference(&expected).collect();
        assert!(
            missing.is_empty(),
            "goldens missing from the {set} set (see tests/golden/README.md): {missing:?}"
        );
        assert!(
            stale.is_empty(),
            "goldens in the {set} set that no scene names: {stale:?}"
        );
    }
}

#[test]
#[ignore = "needs a GPU adapter: scripts/ui-golden.sh"]
fn the_goldens_match() {
    let class = Class::from_env();
    let write = std::env::var_os("LUNEPACK_WRITE_GOLDENS").is_some_and(|v| v == "1");
    let mut renderer = Renderer::new().expect(
        "a GPU adapter is required (this test fails, never skips): run scripts/ui-golden.sh",
    );
    let out = out_dir();
    std::fs::create_dir_all(&out).expect("the output directory");
    if write {
        std::fs::create_dir_all(golden_dir()).expect("the goldens directory");
    }
    // No set for this OS yet: everything is rendered and saved below (CI uploads it), then the test
    // fails with the way to seed one. Writing creates the set, so it never trips this.
    let no_set = !write && names_on_disk(SET).is_empty();
    let mut failures = Vec::new();
    for scene in scenes() {
        let times: Vec<Duration> = scene
            .shots
            .iter()
            .map(|(_, t)| Duration::from_millis(*t))
            .collect();
        let images: Vec<RgbaImage> = renderer
            .render(&scene.script, &times, &options(&scene))
            .expect("the scene renders");
        for ((name, _), image) in scene.shots.iter().zip(&images) {
            let file = format!("{name}.png");
            image
                .write_png(&out.join(&file))
                .expect("the render is saved");
            let golden = golden_dir().join(&file);
            if write {
                image.write_png(&golden).expect("the golden is written");
                continue;
            }
            if no_set {
                continue;
            }
            let Ok(bytes) = std::fs::read(&golden) else {
                failures.push(format!("{name}: no golden at tests/golden/{SET}/{file}"));
                continue;
            };
            let Ok(want) = icon::decode(&bytes) else {
                failures.push(format!("{name}: the golden is not a readable PNG"));
                continue;
            };
            if (want.width, want.height) != (image.width, image.height) {
                failures.push(format!(
                    "{name}: size {}x{}, golden {}x{}",
                    image.width, image.height, want.width, want.height
                ));
                continue;
            }
            let d = diff(&image.rgba, &want.rgba);
            if !d.within(class) {
                let (delta, fraction) = class.limits();
                failures.push(format!(
                    "{name}: max channel delta {} (limit {delta}), {:.2} % of pixels differ (limit {:.2} %), {:?} class",
                    d.max_delta,
                    d.fraction() * 100.0,
                    fraction * 100.0,
                    class
                ));
            }
        }
    }
    assert!(
        !no_set,
        "no golden set for {SET} (tests/golden/{SET}); seed it from the frames this run saved in {} \
         (CI uploads them as the artifact ui-golden-renders-{SET}): see tests/golden/README.md",
        out.display()
    );
    assert!(
        failures.is_empty(),
        "{} golden frame(s) differ; the renders are in {}:\n{}",
        failures.len(),
        out.display(),
        failures.join("\n")
    );
}
