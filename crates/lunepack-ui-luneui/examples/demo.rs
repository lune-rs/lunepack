//! The screens driven by a scripted fake engine.
//!
//! `demo --dump <dir> [--os windows|macos|linux] [--glass]` renders the install flow's screens
//! and transition strips headless into `<dir>` (opaque material unless `--glass`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use lune_ui::motion::MotionTier;
use lunepack_core::ui::Flow;

use lunepack_ui_luneui::render::{RenderOptions, Renderer, Step, Timed, at};
use lunepack_ui_luneui::scenario;
use lunepack_ui_luneui::{Env, Material, Os};

const USAGE: &str = "usage: demo --dump <dir> [--os windows|macos|linux] [--glass] [--batch 1|2|3]";

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

fn shoot(
    r: &mut Renderer,
    dir: &Path,
    opts: &RenderOptions,
    script: &[Timed],
    shots: &[(String, u64)],
) -> Result<(), String> {
    let times: Vec<Duration> = shots.iter().map(|(_, t)| ms(*t)).collect();
    let images = r.render(script, &times, opts).map_err(|e| e.to_string())?;
    for ((name, _), image) in shots.iter().zip(images) {
        image
            .write_png(&dir.join(format!("{name}.png")))
            .map_err(|e| e.to_string())?;
        eprintln!("wrote {name}.png");
    }
    Ok(())
}

fn dump(dir: &Path, os: Os, glass: bool, batch: u32) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let env = Env {
        os,
        material: if glass {
            Material::Glass
        } else {
            Material::Opaque
        },
    };
    let full = RenderOptions {
        env,
        tier: MotionTier::Full,
        scale: 1.0,
        flow: Flow::Install,
    };
    let reduced = RenderOptions {
        tier: MotionTier::Reduced,
        ..full
    };
    let mut r = Renderer::new().map_err(|e| e.to_string())?;
    let one = |name: &str, t: u64| vec![(name.to_owned(), t)];
    if batch == 2 {
        return batch2(&mut r, dir, os, &full, &reduced);
    }
    if batch == 3 {
        return batch3(&mut r, dir, os, &full, &reduced);
    }

    shoot(
        &mut r,
        dir,
        &full,
        &scenario::install_welcome(os, scenario::APP_NAME, true),
        &one("I1", 600),
    )?;
    shoot(
        &mut r,
        dir,
        &full,
        &scenario::install_running(os, 1000),
        &one("I2", 3000),
    )?;
    shoot(
        &mut r,
        dir,
        &full,
        &scenario::install_done(os, 1000, 4000),
        &one("I3", 5500),
    )?;
    shoot(
        &mut r,
        dir,
        &full,
        &scenario::install_failed(os, 1000, 4000, 9),
        &one("I4", 5500),
    )?;

    let strip = |prefix: &str| -> Vec<(String, u64)> {
        [0u64, 60, 120, 180, 240, 300, 360, 430, 600]
            .iter()
            .map(|t| (format!("{prefix}-t{t:04}"), 1000 + t))
            .collect()
    };
    shoot(
        &mut r,
        dir,
        &full,
        &scenario::install_running(os, 1000),
        &strip("I5"),
    )?;
    shoot(
        &mut r,
        dir,
        &reduced,
        &scenario::install_running(os, 1000),
        &strip("I6"),
    )?;

    let sheen: Vec<(String, u64)> = [0u64, 450, 900, 1350, 1800, 2400]
        .iter()
        .map(|t| (format!("I7-t{t:04}"), 3000 + t))
        .collect();
    shoot(
        &mut r,
        dir,
        &full,
        &scenario::install_running(os, 1000),
        &sheen,
    )?;

    let long = "Lunegit Professional Edition for Very Large Repositories and Monorepos";
    shoot(
        &mut r,
        dir,
        &full,
        &scenario::install_welcome(os, long, false),
        &one("I8", 600),
    )?;

    let mut focus = scenario::install_welcome(os, scenario::APP_NAME, true);
    focus.push(at(700, Step::Key(lune_ui::input::NamedKey::Tab)));
    focus.push(at(800, Step::Key(lune_ui::input::NamedKey::Tab)));
    shoot(&mut r, dir, &full, &focus, &one("I9-focus", 1200))?;
    let mut hover = scenario::install_welcome(os, scenario::APP_NAME, true);
    hover.push(at(700, Step::Pointer(410.0, 324.0)));
    shoot(&mut r, dir, &full, &hover, &one("I9-hover", 1200))?;
    Ok(())
}

/// Frames `<prefix>-t<ms>` at `base + t` for each `t`.
fn strip(prefix: &str, base: u64, times: &[u64]) -> Vec<(String, u64)> {
    times
        .iter()
        .map(|t| (format!("{prefix}-t{t:04}"), base + t))
        .collect()
}

const FIVE: [u64; 9] = [0, 60, 120, 180, 240, 300, 360, 430, 600];

fn batch2(
    r: &mut Renderer,
    dir: &Path,
    os: Os,
    full: &RenderOptions,
    reduced: &RenderOptions,
) -> Result<(), String> {
    let upd = |o: &RenderOptions| RenderOptions {
        flow: Flow::Update,
        ..*o
    };
    let (uf, ur) = (upd(full), upd(reduced));
    let one = |name: &str, t: u64| vec![(name.to_owned(), t)];
    shoot(r, dir, &uf, &scenario::update_waiting(), &one("U1", 1000))?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_applying(1000, 74),
        &one("U2", 2500),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_starting(1000, 2000),
        &one("U3", 3500),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_rolled_back(1000, 2000, 3000),
        &one("U4", 4500),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_failed(1000, 3000, 9),
        &one("U5", 4500),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_applying(1000, 74),
        &strip("U6", 1000, &FIVE),
    )?;
    shoot(
        r,
        dir,
        &ur,
        &scenario::update_applying(1000, 74),
        &strip("U7", 1000, &FIVE),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_waiting(),
        &strip("U8f", 1000, &[0, 400, 800, 1200, 1600, 2000, 2400]),
    )?;
    shoot(
        r,
        dir,
        &ur,
        &scenario::update_waiting(),
        &strip("U8r", 1000, &[0, 450, 900, 1350, 1800]),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_rolled_back(1000, 2000, 4000),
        &strip("U9", 4000, &[0, 120, 240, 360, 600]),
    )?;
    shoot(
        r,
        dir,
        full,
        &scenario::install_welcome(os, scenario::APP_NAME, true),
        &strip("W1i", 0, &[0, 60, 120, 180, 250]),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_waiting(),
        &strip("W1u", 0, &[0, 60, 120, 180, 250]),
    )?;
    shoot(
        r,
        dir,
        &ur,
        &scenario::update_waiting(),
        &strip("W1ur", 0, &[0, 120, 250]),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::update_updated(1000, 2000, 4000),
        &strip("W2", 4000, &[0, 60, 120, 180]),
    )?;
    // Batch 1 re-check: the shared bar and transition.
    shoot(
        r,
        dir,
        full,
        &scenario::install_running(os, 1000),
        &one("B1-I2", 3000),
    )?;
    shoot(
        r,
        dir,
        full,
        &scenario::install_running(os, 1000),
        &one("B1-I5-t0430", 1430),
    )?;
    shoot(
        r,
        dir,
        full,
        &scenario::install_running(os, 1000),
        &one("B1-I7-t1350", 4350),
    )?;
    Ok(())
}

fn batch3(
    r: &mut Renderer,
    dir: &Path,
    os: Os,
    full: &RenderOptions,
    reduced: &RenderOptions,
) -> Result<(), String> {
    let (uf, ur) = (
        RenderOptions {
            flow: Flow::Uninstall,
            ..*full
        },
        RenderOptions {
            flow: Flow::Uninstall,
            ..*reduced
        },
    );
    let one = |name: &str, t: u64| vec![(name.to_owned(), t)];
    shoot(
        r,
        dir,
        &uf,
        &scenario::uninstall_confirm(os),
        &one("N1", 600),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::uninstall_removing(os, 1000),
        &one("N2", 3000),
    )?;
    for (name, n) in [("N3", 0), ("N4", 1), ("N5", 6)] {
        let script = scenario::uninstall_done(os, 1000, 4000, scenario::leftovers(os, n));
        shoot(r, dir, &uf, &script, &one(name, 5500))?;
    }
    shoot(
        r,
        dir,
        &uf,
        &scenario::uninstall_failed(os, 1000, 4000, 9),
        &one("N6", 5500),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::uninstall_removing(os, 1000),
        &strip("N7", 1000, &FIVE),
    )?;
    shoot(
        r,
        dir,
        &ur,
        &scenario::uninstall_removing(os, 1000),
        &strip("N8", 1000, &FIVE),
    )?;
    shoot(
        r,
        dir,
        &uf,
        &scenario::uninstall_done(os, 1000, 4000, scenario::leftovers(os, 1)),
        &strip("N9", 4000, &[0, 120, 240, 360, 600]),
    )?;
    // Batch 1 re-check: install's installing -> done transition (the dot colour and rail code).
    let idone = scenario::install_done(os, 1000, 4000);
    let ifull = RenderOptions {
        flow: Flow::Install,
        ..*full
    };
    shoot(r, dir, &ifull, &idone, &strip("B1-I3", 4000, &[0, 120]))?;
    let mut focus = scenario::uninstall_confirm(os);
    focus.push(at(700, Step::Key(lune_ui::input::NamedKey::Tab)));
    focus.push(at(800, Step::Key(lune_ui::input::NamedKey::Tab)));
    shoot(r, dir, &uf, &focus, &one("N10-confirm", 1200))?;
    let mut focus = scenario::uninstall_done(os, 1000, 4000, scenario::leftovers(os, 1));
    focus.push(at(5600, Step::Key(lune_ui::input::NamedKey::Tab)));
    shoot(r, dir, &uf, &focus, &one("N10-leftovers", 6000))?;
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut dir, mut os, mut glass, mut batch) = (None::<PathBuf>, Os::current(), false, 1u32);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dump" => dir = args.next().map(PathBuf::from),
            "--os" => {
                os = match args.next().as_deref() {
                    Some("windows") => Os::Windows,
                    Some("macos") => Os::Macos,
                    Some("linux") => Os::Linux,
                    _ => {
                        eprintln!("{USAGE}");
                        std::process::exit(2);
                    }
                }
            }
            "--glass" => glass = true,
            "--batch" => batch = args.next().and_then(|b| b.parse().ok()).unwrap_or(1),
            _ => {
                eprintln!("{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let Some(dir) = dir else {
        eprintln!("{USAGE}\n(the window mode arrives with the lunepack-ui binary's event loop)");
        std::process::exit(2);
    };
    if let Err(e) = dump(&dir, os, glass, batch) {
        eprintln!("demo: {e}");
        std::process::exit(1);
    }
}
