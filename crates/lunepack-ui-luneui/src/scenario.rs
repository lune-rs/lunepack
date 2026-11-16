//! Scripted engines for the demo and the tests: the messages a real engine would send, at fixed
//! times, and a generated sample icon (no third-party art). A script is sorted by time.

use lunepack_core::progress::Phase;
use lunepack_core::ui::{
    AppCard, ChoiceValue, Details, EngineMsg, Flow, Outcome, PromptKind, StepItem, build_id,
};

use crate::render::{Step, Timed, at};
use crate::strings::Os;

/// The demo app.
pub const APP_NAME: &str = "Lunegit";
/// The demo version.
pub const APP_VERSION: &str = "1.4.0";
/// The demo publisher.
pub const PUBLISHER: &str = "Example Publisher";
/// The demo package's unpacked size.
pub const TOTAL_BYTES: u64 = 61_000_000;

/// Where the demo installs on `os`.
pub fn location(os: Os) -> String {
    match os {
        Os::Windows => "AppData\\Local\\Lunegit".to_owned(),
        Os::Macos => "~/Applications/Lunegit.app".to_owned(),
        Os::Linux => "~/.local/share/lunegit".to_owned(),
    }
}

/// A 128 by 128 PNG icon drawn in code: a dark rounded tile with a small graph of three nodes.
pub fn sample_icon_png() -> Vec<u8> {
    const N: u32 = 128;
    const SS: u32 = 4;
    let k = 64.0 / N as f32;
    // Geometry in a 64-unit box.
    let nodes = [[24.0f32, 18.0], [24.0, 46.0], [42.0, 26.0]];
    let mut path: Vec<[f32; 2]> = vec![[24.0, 23.0], [24.0, 41.0]];
    let (p0, c0, c1, p1) = ([42.0f32, 31.0], [42.0, 39.0], [24.0, 37.0], [24.0, 41.0]);
    for i in 0..=16 {
        let t = i as f32 / 16.0;
        let u = 1.0 - t;
        path.push([
            u * u * u * p0[0]
                + 3.0 * u * u * t * c0[0]
                + 3.0 * u * t * t * c1[0]
                + t * t * t * p1[0],
            u * u * u * p0[1]
                + 3.0 * u * u * t * c0[1]
                + 3.0 * u * t * t * c1[1]
                + t * t * t * p1[1],
        ]);
    }
    let seg_dist = |p: [f32; 2], a: [f32; 2], b: [f32; 2]| {
        let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
        let l2 = dx * dx + dy * dy;
        let t = if l2 > 0.0 {
            (((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / l2).clamp(0.0, 1.0)
        } else {
            0.0
        };
        ((p[0] - a[0] - t * dx).powi(2) + (p[1] - a[1] - t * dy).powi(2)).sqrt()
    };
    let glyph = |p: [f32; 2]| {
        nodes
            .iter()
            .any(|c| ((p[0] - c[0]).hypot(p[1] - c[1]) - 5.0).abs() <= 1.5)
            || path.windows(2).any(|s| seg_dist(p, s[0], s[1]) <= 1.5)
    };
    // The tile: a rounded square 62 wide, corner radius 14, centred in the box.
    let tile_sdf = |p: [f32; 2]| {
        let (hx, hy, r) = (31.0 - 14.0, 31.0 - 14.0, 14.0);
        let (qx, qy) = ((p[0] - 32.0).abs() - hx, (p[1] - 32.0).abs() - hy);
        qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0) - r
    };
    let mut rgba = Vec::with_capacity((N * N * 4) as usize);
    for y in 0..N {
        for x in 0..N {
            let (mut tile, mut edge, mut mark) = (0u32, 0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let p = [
                        (x as f32 + (sx as f32 + 0.5) / SS as f32) * k,
                        (y as f32 + (sy as f32 + 0.5) / SS as f32) * k,
                    ];
                    let d = tile_sdf(p);
                    if d <= 0.0 {
                        tile += 1;
                        if d > -1.0 {
                            edge += 1;
                        }
                        if glyph(p) {
                            mark += 1;
                        }
                    }
                }
            }
            let n = (SS * SS) as f32;
            let (cov, edge, mark) = (tile as f32 / n, edge as f32 / n, mark as f32 / n);
            // Tile #2A2D31, a 1 unit edge of white at 20 %, the graph #D9DCE0 over it.
            let mut c = [0x2Au8, 0x2D, 0x31].map(f32::from);
            for v in &mut c {
                *v += (255.0 - *v) * 0.2 * (edge / cov.max(1e-3)).min(1.0);
            }
            let g = [0xD9u8, 0xDC, 0xE0].map(f32::from);
            let m = (mark / cov.max(1e-3)).min(1.0);
            let px: Vec<u8> = (0..3)
                .map(|i| (c[i] + (g[i] - c[i]) * m).round().clamp(0.0, 255.0) as u8)
                .chain(std::iter::once((cov * 255.0).round() as u8))
                .collect();
            rgba.extend_from_slice(&px);
        }
    }
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, N, N);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    if let Ok(mut w) = enc.write_header() {
        let _ = w.write_image_data(&rgba);
    }
    out
}

/// The hello of an install: the demo app on `os`, with or without an icon.
pub fn install_hello(os: Os, name: &str, icon: bool) -> EngineMsg {
    EngineMsg::Hello {
        build_id: build_id(),
        flow: Flow::Install,
        app: AppCard {
            name: name.to_owned(),
            version: APP_VERSION.to_owned(),
            from_version: None,
            publisher: Some(PUBLISHER.to_owned()),
            icon_png: icon.then(sample_icon_png),
        },
        details: Details {
            location: Some(location(os)),
            size_bytes: Some(TOTAL_BYTES),
        },
    }
}

/// The welcome screen, open at 0 ms.
pub fn install_welcome(os: Os, name: &str, icon: bool) -> Vec<Timed> {
    vec![
        at(0, Step::Engine(install_hello(os, name, icon))),
        at(
            0,
            Step::Engine(EngineMsg::Prompt {
                id: 1,
                kind: PromptKind::Welcome,
            }),
        ),
    ]
}

/// The welcome screen, the user's Install at `proceed_ms`, then a run that is 67 % along (40.9 of 61 MB)
/// 1.5 s later: the check done and "Unpack files" running.
pub fn install_running(os: Os, proceed_ms: u64) -> Vec<Timed> {
    let mut s = install_welcome(os, APP_NAME, true);
    s.push(at(proceed_ms, Step::Choose(ChoiceValue::Proceed)));
    s.push(at(
        proceed_ms + 10,
        Step::Engine(EngineMsg::Cancellable(true)),
    ));
    s.push(at(
        proceed_ms + 300,
        Step::Engine(EngineMsg::Step {
            item: StepItem::Verify,
        }),
    ));
    s.push(at(
        proceed_ms + 500,
        Step::Engine(EngineMsg::Progress {
            phase: Phase::Stage,
            done: 40_900_000,
            total: TOTAL_BYTES,
        }),
    ));
    s
}

/// A finished install at `done_ms`: all steps done, the outcome and the done prompt.
pub fn install_done(os: Os, proceed_ms: u64, done_ms: u64) -> Vec<Timed> {
    let mut s = install_running(os, proceed_ms);
    for item in [StepItem::Stage, StepItem::Integrate, StepItem::Commit] {
        s.push(at(done_ms, Step::Engine(EngineMsg::Step { item })));
    }
    s.push(at(done_ms, Step::Engine(EngineMsg::Cancellable(false))));
    s.push(at(
        done_ms,
        Step::Engine(EngineMsg::Outcome(Outcome::Installed)),
    ));
    s.push(at(
        done_ms,
        Step::Engine(EngineMsg::Prompt {
            id: 2,
            kind: PromptKind::Done,
        }),
    ));
    s
}

/// A failed install at `fail_ms` with the runtime's `code` (9 is a filesystem failure).
pub fn install_failed(os: Os, proceed_ms: u64, fail_ms: u64, code: u32) -> Vec<Timed> {
    let mut s = install_running(os, proceed_ms);
    s.push(at(fail_ms, Step::Engine(EngineMsg::Cancellable(false))));
    s.push(at(
        fail_ms,
        Step::Engine(EngineMsg::Outcome(Outcome::Failed { code })),
    ));
    s.push(at(
        fail_ms,
        Step::Engine(EngineMsg::Prompt {
            id: 2,
            kind: PromptKind::Failed,
        }),
    ));
    s
}

/// The version an update goes to.
pub const NEW_VERSION: &str = "1.5.0";

/// The hello of an update window: the demo app going from [`APP_VERSION`] to [`NEW_VERSION`].
pub fn update_hello() -> EngineMsg {
    EngineMsg::Hello {
        build_id: build_id(),
        flow: Flow::Update,
        app: AppCard {
            name: APP_NAME.to_owned(),
            version: NEW_VERSION.to_owned(),
            from_version: Some(APP_VERSION.to_owned()),
            publisher: None,
            icon_png: Some(sample_icon_png()),
        },
        details: Details {
            location: None,
            size_bytes: None,
        },
    }
}

/// The update window waiting for the app to close, open at 0 ms.
pub fn update_waiting() -> Vec<Timed> {
    vec![at(0, Step::Engine(update_hello()))]
}

/// Waiting, then applying from `apply_ms` with `percent` done.
pub fn update_applying(apply_ms: u64, percent: u64) -> Vec<Timed> {
    let mut s = update_waiting();
    s.push(at(
        apply_ms,
        Step::Engine(EngineMsg::Progress {
            phase: Phase::Apply,
            done: percent,
            total: 100,
        }),
    ));
    s
}

/// Applying (74 %), then starting the new version from `start_ms`.
pub fn update_starting(apply_ms: u64, start_ms: u64) -> Vec<Timed> {
    let mut s = update_applying(apply_ms, 74);
    s.push(at(
        start_ms,
        Step::Engine(EngineMsg::Progress {
            phase: Phase::Launch,
            done: 0,
            total: 0,
        }),
    ));
    s
}

/// Starting, then rolled back at `rb_ms`, with the OK prompt.
pub fn update_rolled_back(apply_ms: u64, start_ms: u64, rb_ms: u64) -> Vec<Timed> {
    let mut s = update_starting(apply_ms, start_ms);
    s.push(at(
        rb_ms,
        Step::Engine(EngineMsg::Outcome(Outcome::RolledBack {
            from: NEW_VERSION.to_owned(),
            to: APP_VERSION.to_owned(),
        })),
    ));
    s.push(at(
        rb_ms,
        Step::Engine(EngineMsg::Prompt {
            id: 1,
            kind: PromptKind::RolledBack,
        }),
    ));
    s
}

/// Applying (74 %), then a failure with `code` at `fail_ms`, with the failed prompt.
pub fn update_failed(apply_ms: u64, fail_ms: u64, code: u32) -> Vec<Timed> {
    let mut s = update_applying(apply_ms, 74);
    s.push(at(
        fail_ms,
        Step::Engine(EngineMsg::Outcome(Outcome::Failed { code })),
    ));
    s.push(at(
        fail_ms,
        Step::Engine(EngineMsg::Prompt {
            id: 1,
            kind: PromptKind::Failed,
        }),
    ));
    s
}

/// Starting, then `Updated` at `done_ms` (the window fades out).
pub fn update_updated(apply_ms: u64, start_ms: u64, done_ms: u64) -> Vec<Timed> {
    let mut s = update_starting(apply_ms, start_ms);
    s.push(at(
        done_ms,
        Step::Engine(EngineMsg::Outcome(Outcome::Updated)),
    ));
    s
}

/// The hello of an uninstall.
pub fn uninstall_hello(os: Os) -> EngineMsg {
    EngineMsg::Hello {
        build_id: build_id(),
        flow: Flow::Uninstall,
        app: AppCard {
            name: APP_NAME.to_owned(),
            version: APP_VERSION.to_owned(),
            from_version: None,
            publisher: None,
            icon_png: Some(sample_icon_png()),
        },
        details: Details {
            location: Some(location(os)),
            size_bytes: None,
        },
    }
}

/// The confirm screen, open at 0 ms.
pub fn uninstall_confirm(os: Os) -> Vec<Timed> {
    vec![
        at(0, Step::Engine(uninstall_hello(os))),
        at(
            0,
            Step::Engine(EngineMsg::Prompt {
                id: 1,
                kind: PromptKind::Confirm,
            }),
        ),
    ]
}

/// Confirm, the user's Uninstall at `proceed_ms`, then removing, 40 % along 1.5 s later with the
/// shortcuts removed.
pub fn uninstall_removing(os: Os, proceed_ms: u64) -> Vec<Timed> {
    let mut s = uninstall_confirm(os);
    s.push(at(proceed_ms, Step::Choose(ChoiceValue::Proceed)));
    s.push(at(
        proceed_ms + 300,
        Step::Engine(EngineMsg::Step {
            item: StepItem::Integrate,
        }),
    ));
    s.push(at(
        proceed_ms + 500,
        Step::Engine(EngineMsg::Progress {
            phase: Phase::Uninstall,
            done: 40,
            total: 100,
        }),
    ));
    s
}

/// Removing, then done at `done_ms` with `leftovers`.
pub fn uninstall_done(os: Os, proceed_ms: u64, done_ms: u64, leftovers: Vec<String>) -> Vec<Timed> {
    let mut s = uninstall_removing(os, proceed_ms);
    s.push(at(
        done_ms,
        Step::Engine(EngineMsg::Step {
            item: StepItem::Remove,
        }),
    ));
    s.push(at(
        done_ms,
        Step::Engine(EngineMsg::Outcome(Outcome::Uninstalled { leftovers })),
    ));
    s.push(at(
        done_ms,
        Step::Engine(EngineMsg::Prompt {
            id: 2,
            kind: PromptKind::Done,
        }),
    ));
    s
}

/// Removing, then a failure with `code` at `fail_ms`.
pub fn uninstall_failed(os: Os, proceed_ms: u64, fail_ms: u64, code: u32) -> Vec<Timed> {
    let mut s = uninstall_removing(os, proceed_ms);
    s.push(at(
        fail_ms,
        Step::Engine(EngineMsg::Outcome(Outcome::UninstallFailed { code })),
    ));
    s.push(at(
        fail_ms,
        Step::Engine(EngineMsg::Prompt {
            id: 2,
            kind: PromptKind::Failed,
        }),
    ));
    s
}

/// `n` demo leftover paths under the install location of `os`; the first is over 200 characters.
pub fn leftovers(os: Os, n: usize) -> Vec<String> {
    let base = location(os);
    (0..n)
        .map(|i| {
            if i == 0 && n > 1 {
                format!("{base}/app-1.4.0/{}", "very-long-folder-name/".repeat(10))
            } else {
                format!("{base}/app-1.4.{i}")
            }
        })
        .collect()
}
