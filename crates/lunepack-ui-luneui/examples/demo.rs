//! The screens driven by a scripted fake engine.
//!
//! `demo --dump <dir> [--os windows|macos|linux] [--glass]` renders the install flow's screens
//! and transition strips headless into `<dir>` (opaque material unless `--glass`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use lune_ui::motion::MotionTier;

use lunepack_ui_luneui::render::{RenderOptions, Renderer, Step, Timed, at};
use lunepack_ui_luneui::scenario;
use lunepack_ui_luneui::{Env, Material, Os};

const USAGE: &str = "usage: demo --dump <dir> [--os windows|macos|linux] [--glass]";

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

fn dump(dir: &Path, os: Os, glass: bool) -> Result<(), String> {
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
    };
    let reduced = RenderOptions {
        tier: MotionTier::Reduced,
        ..full
    };
    let mut r = Renderer::new().map_err(|e| e.to_string())?;
    let one = |name: &str, t: u64| vec![(name.to_owned(), t)];

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

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut dir, mut os, mut glass) = (None::<PathBuf>, Os::current(), false);
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
    if let Err(e) = dump(&dir, os, glass) {
        eprintln!("demo: {e}");
        std::process::exit(1);
    }
}
