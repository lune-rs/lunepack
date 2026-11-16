//! The screens without a GPU: the install flow's accessibility tree, keyboard, answers, motion
//! rules and defensive rendering, driven with the toolkit's fake text system.

use std::time::Duration;

use lune_ui::access::{Role, Value};
use lune_ui::input::NamedKey;
use lune_ui::motion::MotionTier;
use lune_ui::scene::Scene;
use lune_ui::testing::FakeText;

use lunepack_core::ui::{ChoiceValue, EngineMsg, Flow, Screen, UiMsg};
use lunepack_ui_luneui::render::{Player, RenderOptions, Step, Timed, at};
use lunepack_ui_luneui::{Env, Material, Os, icon, scenario};

fn opts(tier: MotionTier) -> RenderOptions {
    RenderOptions {
        env: Env {
            os: Os::Windows,
            material: Material::Opaque,
        },
        tier,
        scale: 1.0,
        flow: Flow::Install,
    }
}

/// Plays `script` frame by frame every 10 ms up to `until_ms` and returns the player and the last
/// frame's scene, tree and answer.
fn run(
    script: &[Timed],
    until_ms: u64,
    tier: MotionTier,
) -> (Player, Scene, lune_ui::access::SemanticTree, Vec<UiMsg>) {
    let mut player = Player::new(opts(tier));
    let mut text = FakeText;
    let mut next = 0;
    let (mut scene, mut tree) = (Scene::default(), Default::default());
    for ms in (0..=until_ms).step_by(10) {
        let now = Duration::from_millis(ms);
        while let Some(item) = script.get(next).filter(|s| s.at <= now) {
            next += 1;
            player.play(item).expect("the script is valid");
        }
        let (s, out, _) = player.frame(&mut text, now);
        scene = s;
        tree = out.tree;
    }
    let answers = player.take_answers();
    (player, scene, tree, answers)
}

fn find<'a>(
    tree: &'a lune_ui::access::SemanticTree,
    role: Role,
    name: &str,
) -> Option<&'a lune_ui::access::Node> {
    tree.nodes.iter().find(|n| n.role == role && n.name == name)
}

fn welcome() -> Vec<Timed> {
    scenario::install_welcome(Os::Windows, scenario::APP_NAME, true)
}

fn proceed_answer(answers: &[UiMsg]) -> bool {
    matches!(
        answers,
        [UiMsg::Choice {
            value: ChoiceValue::Proceed,
            ..
        }]
    )
}

#[test]
fn the_icon_decodes_within_its_caps_and_bad_ones_are_refused() {
    let ok = icon::decode(&scenario::sample_icon_png()).expect("the sample decodes");
    assert_eq!((ok.width, ok.height), (128, 128));
    assert!(ok.length_ok());
    assert!(
        ok.rgba.as_chunks::<4>().0.iter().any(|p| p[3] == 0),
        "round corners are transparent"
    );

    let side = |w: u32, h: u32| {
        let mut out = Vec::new();
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().unwrap();
        writer
            .write_image_data(&vec![0u8; (w * h * 4) as usize])
            .unwrap();
        drop(writer);
        out
    };
    assert!(icon::decode(&side(1024, 1)).is_ok());
    assert!(matches!(
        icon::decode(&side(1025, 1)),
        Err(icon::IconError::Size)
    ));
    assert!(matches!(
        icon::decode(&side(1, 1025)),
        Err(icon::IconError::Size)
    ));
    assert!(icon::decode(b"not a png").is_err());
    let good = scenario::sample_icon_png();
    assert!(
        icon::decode(&good[..good.len() / 2]).is_err(),
        "a truncated file is refused"
    );
    assert!(icon::decode(&[]).is_err());
}

#[test]
fn an_icon_that_does_not_decode_leaves_the_monogram() {
    let mut hello = scenario::install_welcome(Os::Windows, "Lunegit", false);
    if let Step::Engine(EngineMsg::Hello { app, .. }) = &mut hello[0].step {
        app.icon_png = Some(b"definitely not a png".to_vec());
    }
    let (player, _, _, _) = run(&hello, 600, MotionTier::Full);
    assert!(player.model.icon().is_none());
    assert_eq!(player.model.screen(), Screen::InstallWelcome);
}

#[test]
fn the_welcome_screen_names_every_control() {
    let (_, _, tree, _) = run(&welcome(), 600, MotionTier::Full);
    for name in ["Install", "Cancel", "Minimize", "Close"] {
        assert!(find(&tree, Role::Button, name).is_some(), "button {name}");
    }
    let dialog = find(&tree, Role::Dialog, "Install Lunegit").expect("the window is a dialog");
    assert!(!dialog.children.is_empty());
    assert!(
        tree.nodes
            .iter()
            .any(|n| n.role == Role::StaticText && n.name == "Lunegit")
    );
    assert!(
        tree.nodes
            .iter()
            .any(|n| n.name.starts_with("Step 1 of 3: Welcome, current"))
    );
    assert!(tree.nodes.iter().any(|n| n.role == Role::Image));
}

#[test]
fn a_publisher_only_appears_when_the_package_names_one() {
    let (_, _, with, _) = run(&welcome(), 600, MotionTier::Full);
    let mut none = welcome();
    if let Step::Engine(EngineMsg::Hello { app, .. }) = &mut none[0].step {
        app.publisher = None;
    }
    let (_, scene_none, _, _) = run(&none, 600, MotionTier::Full);
    let (_, scene_some, _, _) = run(&welcome(), 600, MotionTier::Full);
    let texts = |s: &Scene| s.layers.iter().map(|l| l.texts.len()).sum::<usize>();
    assert!(
        texts(&scene_none) < texts(&scene_some),
        "the publisher row is left out"
    );
    assert!(!with.nodes.is_empty());
}

#[test]
fn the_installing_screen_has_a_named_progress_bar_with_a_value() {
    let (_, _, tree, _) = run(
        &scenario::install_running(Os::Windows, 1000),
        3000,
        MotionTier::Full,
    );
    let bar = find(&tree, Role::Progress, "Installation progress").expect("a progress node");
    match &bar.value {
        Some(Value::Number {
            value, min, max, ..
        }) => {
            assert_eq!((*min, *max), (0.0, 100.0));
            assert!(
                (value - 67.0).abs() < 1.5,
                "67 % along (40.9 of 61 MB), got {value}"
            );
        }
        other => panic!("no value: {other:?}"),
    }
    assert!(find(&tree, Role::Button, "Cancel").is_some());
    assert!(
        find(&tree, Role::Button, "Install").is_none(),
        "the welcome screen is gone"
    );
}

#[test]
fn enter_answers_the_primary_button_and_escape_cancels() {
    let mut s = welcome();
    s.push(at(700, Step::Key(NamedKey::Enter)));
    let (player, _, _, answers) = run(&s, 800, MotionTier::Full);
    assert!(proceed_answer(&answers), "{answers:?}");
    assert_eq!(
        player.model.screen(),
        Screen::Installing,
        "the answer was recorded"
    );

    let mut s = welcome();
    s.push(at(700, Step::Key(NamedKey::Escape)));
    let (_, _, _, answers) = run(&s, 800, MotionTier::Full);
    assert!(
        matches!(
            answers.as_slice(),
            [UiMsg::Choice {
                value: ChoiceValue::Cancel,
                ..
            }]
        ),
        "{answers:?}"
    );
}

#[test]
fn tab_order_follows_the_visual_order() {
    // Cancel is left of Install: one Tab then Enter activates Cancel, two Tabs then Enter Install.
    let mut s = welcome();
    s.push(at(700, Step::Key(NamedKey::Tab)));
    s.push(at(800, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run(&s, 900, MotionTier::Full);
    assert!(
        matches!(
            answers.as_slice(),
            [UiMsg::Choice {
                value: ChoiceValue::Cancel,
                ..
            }]
        ),
        "{answers:?}"
    );

    let mut s = welcome();
    s.push(at(700, Step::Key(NamedKey::Tab)));
    s.push(at(800, Step::Key(NamedKey::Tab)));
    s.push(at(900, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run(&s, 1000, MotionTier::Full);
    assert!(proceed_answer(&answers), "{answers:?}");
}

#[test]
fn a_click_on_install_answers_proceed_and_nothing_else_does() {
    let mut s = welcome();
    s.push(at(700, Step::Click(520.0, 324.0)));
    let (_, _, _, answers) = run(&s, 800, MotionTier::Full);
    assert!(proceed_answer(&answers), "{answers:?}");

    let mut s = welcome();
    s.push(at(700, Step::Click(300.0, 200.0)));
    let (_, _, _, answers) = run(&s, 800, MotionTier::Full);
    assert!(answers.is_empty(), "{answers:?}");
}

#[test]
fn the_window_close_button_answers_like_the_screens_cancel() {
    let mut s = welcome();
    s.push(at(700, Step::Click(540.0, 12.0)));
    let (_, _, _, answers) = run(&s, 800, MotionTier::Full);
    assert!(
        matches!(
            answers.as_slice(),
            [UiMsg::Choice {
                value: ChoiceValue::Cancel,
                ..
            }]
        ),
        "{answers:?}"
    );
}

#[test]
fn before_the_prompt_opens_nothing_can_be_answered() {
    let hello_only = vec![welcome().remove(0), at(700, Step::Key(NamedKey::Enter))];
    let (player, _, tree, answers) = run(&hello_only, 800, MotionTier::Full);
    assert!(answers.is_empty());
    assert_eq!(player.model.screen(), Screen::InstallWelcome);
    let install = find(&tree, Role::Button, "Install").expect("drawn");
    assert!(
        install.states.contains(lune_ui::access::State::Disabled),
        "the buttons wait for the prompt"
    );
}

#[test]
fn the_running_screen_cancels_only_while_the_engine_allows_it() {
    let mut s = scenario::install_running(Os::Windows, 1000);
    s.push(at(3100, Step::Key(NamedKey::Escape)));
    let (_, _, _, answers) = run(&s, 3200, MotionTier::Full);
    assert!(
        matches!(answers.as_slice(), [_, UiMsg::Cancel]),
        "{answers:?}"
    );

    // Not cancellable: the button is disabled and Escape answers nothing.
    let mut s = scenario::install_running(Os::Windows, 1000);
    s.retain(|t| !matches!(t.step, Step::Engine(EngineMsg::Cancellable(_))));
    s.push(at(3100, Step::Key(NamedKey::Escape)));
    let (_, _, tree, answers) = run(&s, 3200, MotionTier::Full);
    assert!(
        proceed_answer(&answers),
        "only the earlier proceed: {answers:?}"
    );
    let cancel = find(&tree, Role::Button, "Cancel").expect("drawn");
    assert!(cancel.states.contains(lune_ui::access::State::Disabled));
}

#[test]
fn the_done_screen_finishes_with_the_checkbox_choice() {
    let done = scenario::install_done(Os::Windows, 1000, 4000);
    let (_, _, tree, _) = run(&done, 5500, MotionTier::Full);
    assert!(find(&tree, Role::Checkbox, "Open Lunegit now").is_some());
    assert!(find(&tree, Role::Button, "Finish").is_some());

    let mut s = done.clone();
    s.push(at(5600, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run(&s, 5700, MotionTier::Full);
    assert!(
        matches!(
            answers.last(),
            Some(UiMsg::Choice {
                value: ChoiceValue::Finish { launch: true },
                ..
            })
        ),
        "launches by default: {answers:?}"
    );

    // Tab to the checkbox, Space clears it, Tab to Finish, Enter.
    let mut s = done.clone();
    s.push(at(5600, Step::Key(NamedKey::Tab)));
    s.push(at(5700, Step::Key(NamedKey::Space)));
    s.push(at(5800, Step::Key(NamedKey::Tab)));
    s.push(at(5900, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run(&s, 6000, MotionTier::Full);
    assert!(
        matches!(
            answers.last(),
            Some(UiMsg::Choice {
                value: ChoiceValue::Finish { launch: false },
                ..
            })
        ),
        "{answers:?}"
    );

    // Escape is not an answer here: the screen has no Cancel or Close.
    let mut s = done;
    s.push(at(5600, Step::Key(NamedKey::Escape)));
    let (_, _, _, answers) = run(&s, 5700, MotionTier::Full);
    assert!(!answers.iter().any(|a| matches!(
        a,
        UiMsg::Choice {
            value: ChoiceValue::Finish { .. },
            ..
        }
    )));
}

#[test]
fn the_failed_screen_retries_on_enter_and_closes_on_escape() {
    let failed = scenario::install_failed(Os::Windows, 1000, 4000, 9);
    let (_, _, tree, _) = run(&failed, 5500, MotionTier::Full);
    for name in ["Copy details", "Close", "Try again"] {
        assert!(find(&tree, Role::Button, name).is_some(), "{name}");
    }
    let alert = find(
        &tree,
        Role::Alert,
        "Another program is using the Lunegit folder, so its files couldn't be written. Close it and try again.",
    );
    assert!(alert.is_some());

    let mut s = failed.clone();
    s.push(at(5600, Step::Key(NamedKey::Enter)));
    let (player, _, _, answers) = run(&s, 5700, MotionTier::Full);
    assert!(matches!(
        answers.last(),
        Some(UiMsg::Choice {
            value: ChoiceValue::Retry,
            ..
        })
    ));
    assert_eq!(
        player.model.screen(),
        Screen::Installing,
        "a retry goes back to installing"
    );

    let mut s = failed;
    s.push(at(5600, Step::Key(NamedKey::Escape)));
    let (_, _, _, answers) = run(&s, 5700, MotionTier::Full);
    assert!(matches!(
        answers.last(),
        Some(UiMsg::Choice {
            value: ChoiceValue::Close,
            ..
        })
    ));
}

#[test]
fn a_closed_window_draws_nothing_and_answers_nothing() {
    let mut s = scenario::install_failed(Os::Windows, 1000, 4000, 9);
    s.push(at(5000, Step::Choose(ChoiceValue::Close)));
    s.push(at(5010, Step::Engine(EngineMsg::Close)));
    let (player, _, tree, _) = run(&s, 5100, MotionTier::Full);
    assert!(player.model.is_closed());
    assert!(tree.nodes.is_empty());
}

#[test]
fn an_over_long_name_and_an_odd_location_render_without_overflow_or_panic() {
    let mut s = welcome();
    if let Step::Engine(EngineMsg::Hello { app, details, .. }) = &mut s[0].step {
        app.name = "W".repeat(300);
        app.publisher = Some("P".repeat(300));
        details.location = Some("/very/long/".repeat(300));
    }
    let (_, scene, tree, _) = run(&s, 600, MotionTier::Full);
    assert!(find(&tree, Role::Button, "Install").is_some());
    // Everything drawn stays inside the window (text clips are the window's at most).
    for layer in scene.in_order() {
        for t in &layer.texts {
            assert!(t.x < 560.0 && t.y < 360.0, "text at ({}, {})", t.x, t.y);
        }
    }
}

/// The left-aligned texts' x positions of the main area (the right-aligned percentage moves with
/// its own width, so it is left out).
fn text_xs(scene: &Scene) -> Vec<i32> {
    let mut xs: Vec<i32> = scene
        .layers
        .iter()
        .flat_map(|l| l.texts.iter())
        .filter(|t| (190.0..400.0).contains(&t.x))
        .map(|t| (t.x * 10.0).round() as i32)
        .collect();
    xs.sort();
    xs.dedup();
    xs
}

#[test]
fn reduced_motion_never_translates_content_and_full_does() {
    let script = scenario::install_running(Os::Windows, 1000);
    // 300 ms after the proceed the new content is arriving.
    let (_, settled, _, _) = run(&script, 3000, MotionTier::Reduced);
    let (_, arriving, _, _) = run(&script, 1300, MotionTier::Reduced);
    assert_eq!(
        text_xs(&arriving),
        text_xs(&settled),
        "Reduced keeps the text where it ends up"
    );

    let (_, settled, _, _) = run(&script, 3000, MotionTier::Full);
    let (_, arriving, _, _) = run(&script, 1300, MotionTier::Full);
    assert_ne!(
        text_xs(&arriving),
        text_xs(&settled),
        "Full slides the content in"
    );
}

#[test]
fn a_frame_is_a_pure_function_of_the_script_and_the_time() {
    let script = scenario::install_running(Os::Windows, 1000);
    for ms in [1090, 1200, 1330, 1500] {
        let (_, a, _, _) = run(&script, ms, MotionTier::Full);
        let (_, b, _, _) = run(&script, ms, MotionTier::Full);
        assert_eq!(a, b, "at {ms} ms");
    }
}

#[test]
fn a_still_screen_asks_for_no_more_frames() {
    let mut player = Player::new(opts(MotionTier::Full));
    let mut text = FakeText;
    for item in &welcome() {
        player.play(item).unwrap();
    }
    let mut last = lune_ui::input::Repaint::Now;
    for ms in (0..=1000).step_by(10) {
        let (_, out, _) = player.frame(&mut text, Duration::from_millis(ms));
        last = out.repaint;
    }
    assert_eq!(
        last,
        lune_ui::input::Repaint::Idle,
        "the welcome screen is static once settled"
    );

    // The running screen keeps asking (the sheen, the spinner and the breathing glow).
    let mut player = Player::new(opts(MotionTier::Full));
    for item in &scenario::install_running(Os::Windows, 1000) {
        player.play(item).unwrap();
    }
    let (_, out, _) = player.frame(&mut text, Duration::from_millis(3000));
    assert_ne!(out.repaint, lune_ui::input::Repaint::Idle);
}

// ---- the update window ----

fn flow_opts(flow: Flow, tier: MotionTier) -> RenderOptions {
    RenderOptions { flow, ..opts(tier) }
}

/// `run` for another flow's window.
fn run_flow(
    flow: Flow,
    script: &[Timed],
    until_ms: u64,
) -> (Player, Scene, lune_ui::access::SemanticTree, Vec<UiMsg>) {
    let mut player = Player::new(flow_opts(flow, MotionTier::Full));
    let mut text = FakeText;
    let mut next = 0;
    let (mut scene, mut tree) = (Scene::default(), Default::default());
    for ms in (0..=until_ms).step_by(10) {
        let now = Duration::from_millis(ms);
        while let Some(item) = script.get(next).filter(|s| s.at <= now) {
            next += 1;
            player.play(item).expect("the script is valid");
        }
        let (s, out, _) = player.frame(&mut text, now);
        scene = s;
        tree = out.tree;
    }
    let answers = player.take_answers();
    (player, scene, tree, answers)
}

fn only(answers: &[UiMsg], value: ChoiceValue) -> bool {
    matches!(answers, [UiMsg::Choice { value: v, .. }] if *v == value)
}

#[test]
fn the_update_window_has_minimize_only_and_a_busy_bar_while_waiting() {
    let (_, _, tree, answers) = run_flow(Flow::Update, &scenario::update_waiting(), 1000);
    assert!(find(&tree, Role::Button, "Minimize").is_some());
    assert!(
        find(&tree, Role::Button, "Close").is_none(),
        "no Close caption on any update screen"
    );
    let bar = find(&tree, Role::Progress, "Waiting for the app to close").expect("a bar");
    assert!(bar.states.contains(lune_ui::access::State::Busy));
    assert!(bar.value.is_none(), "indeterminate has no value");
    assert!(answers.is_empty());
    let dialog = find(&tree, Role::Dialog, "Update Lunegit").expect("a dialog");
    assert_eq!((dialog.bounds.w, dialog.bounds.h), (440.0, 180.0));
}

#[test]
fn escape_and_enter_do_nothing_while_an_update_runs() {
    for script in [
        scenario::update_waiting(),
        scenario::update_applying(1000, 74),
        scenario::update_starting(1000, 2000),
    ] {
        let mut s = script;
        s.push(at(5000, Step::Key(NamedKey::Escape)));
        s.push(at(5100, Step::Key(NamedKey::Enter)));
        let (_, _, _, answers) = run_flow(Flow::Update, &s, 5200);
        assert!(answers.is_empty(), "{answers:?}");
    }
}

#[test]
fn the_applying_screen_shows_one_fraction() {
    let (_, _, tree, _) = run_flow(Flow::Update, &scenario::update_applying(1000, 74), 2500);
    let bar = find(&tree, Role::Progress, "Updating").expect("a bar");
    match &bar.value {
        Some(Value::Number { value, .. }) => assert!((value - 74.0).abs() < 1.0, "{value}"),
        other => panic!("{other:?}"),
    }
    assert!(
        tree.nodes
            .iter()
            .any(|n| n.name == "Switching versions \u{b7} 74%"),
        "the caption names the same percentage"
    );
}

#[test]
fn a_rolled_back_update_is_acknowledged_with_enter_and_not_with_escape() {
    let base = scenario::update_rolled_back(1000, 2000, 3000);
    let (_, _, tree, _) = run_flow(Flow::Update, &base, 4000);
    assert!(find(&tree, Role::Button, "OK").is_some());
    assert!(
        tree.nodes
            .iter()
            .any(|n| n.name == "1.5.0 didn't start correctly, so 1.4.0 is back.")
    );
    let mut s = base.clone();
    s.push(at(4100, Step::Key(NamedKey::Escape)));
    let (_, _, _, answers) = run_flow(Flow::Update, &s, 4200);
    assert!(answers.is_empty(), "{answers:?}");
    let mut s = base;
    s.push(at(4100, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run_flow(Flow::Update, &s, 4200);
    assert!(only(&answers, ChoiceValue::Acknowledge), "{answers:?}");
}

#[test]
fn a_failed_update_closes_on_enter_and_escape_and_tabs_copy_then_close() {
    let base = scenario::update_failed(1000, 3000, 9);
    let (_, _, tree, _) = run_flow(Flow::Update, &base, 4000);
    for name in ["Copy details", "Close"] {
        assert!(find(&tree, Role::Button, name).is_some(), "{name}");
    }
    for key in [NamedKey::Enter, NamedKey::Escape] {
        let mut s = base.clone();
        s.push(at(4100, Step::Key(key)));
        let (_, _, _, answers) = run_flow(Flow::Update, &s, 4200);
        assert!(only(&answers, ChoiceValue::Close), "{key:?}: {answers:?}");
    }
    // Tab to Copy details first (it only copies), a second Tab reaches Close.
    let mut s = base;
    s.push(at(4100, Step::Key(NamedKey::Tab)));
    s.push(at(4200, Step::Key(NamedKey::Tab)));
    s.push(at(4300, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run_flow(Flow::Update, &s, 4400);
    assert!(only(&answers, ChoiceValue::Close), "{answers:?}");
}

#[test]
fn the_update_window_is_closable_after_it_fades_out() {
    let (player, _, _, _) = run_flow(
        Flow::Update,
        &scenario::update_updated(1000, 2000, 4000),
        4100,
    );
    let at_ms = |ms| Duration::from_millis(ms);
    assert!(
        !player.model.closable(at_ms(4100), MotionTier::Full),
        "still fading"
    );
    assert!(player.model.closable(at_ms(4180), MotionTier::Full));
    assert!(
        player.model.closable(at_ms(4000), MotionTier::Off),
        "Off closes at once"
    );
    let (player, _, _, _) = run_flow(Flow::Update, &scenario::update_starting(1000, 2000), 4100);
    assert!(
        !player.model.closable(at_ms(9000), MotionTier::Full),
        "not before Updated"
    );
}

// ---- the uninstall flow ----

#[test]
fn the_uninstall_confirm_screen_answers_proceed_and_cancel() {
    let base = scenario::uninstall_confirm(Os::Windows);
    let (_, _, tree, _) = run_flow(Flow::Uninstall, &base, 600);
    for name in ["Cancel", "Uninstall", "Close"] {
        assert!(find(&tree, Role::Button, name).is_some(), "{name}");
    }
    assert!(
        find(&tree, Role::Button, "Minimize").is_none(),
        "Close only"
    );
    assert!(find(&tree, Role::Dialog, "Uninstall Lunegit").is_some());
    assert!(
        tree.nodes
            .iter()
            .any(|n| n.name == "Its entry in Apps & features")
    );

    let mut s = base.clone();
    s.push(at(700, Step::Key(NamedKey::Enter)));
    let (player, _, _, answers) = run_flow(Flow::Uninstall, &s, 800);
    assert!(only(&answers, ChoiceValue::Proceed), "{answers:?}");
    assert_eq!(player.model.screen(), Screen::Uninstalling);

    let mut s = base.clone();
    s.push(at(700, Step::Key(NamedKey::Escape)));
    let (_, _, _, answers) = run_flow(Flow::Uninstall, &s, 800);
    assert!(only(&answers, ChoiceValue::Cancel), "{answers:?}");

    let mut s = base.clone();
    s.push(at(700, Step::Click(546.0, 12.0)));
    let (_, _, _, answers) = run_flow(Flow::Uninstall, &s, 800);
    assert!(
        only(&answers, ChoiceValue::Cancel),
        "the Close caption cancels: {answers:?}"
    );

    let mut s = base;
    s.push(at(700, Step::Key(NamedKey::Tab)));
    s.push(at(800, Step::Key(NamedKey::Tab)));
    s.push(at(900, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run_flow(Flow::Uninstall, &s, 1000);
    assert!(
        only(&answers, ChoiceValue::Proceed),
        "Tab, Tab reaches Uninstall: {answers:?}"
    );
}

#[test]
fn the_removing_screen_shows_one_fraction_and_the_current_step() {
    let (_, _, tree, _) = run_flow(
        Flow::Uninstall,
        &scenario::uninstall_removing(Os::Windows, 1000),
        3000,
    );
    let bar = find(&tree, Role::Progress, "Removing").expect("a bar");
    match &bar.value {
        Some(Value::Number { value, .. }) => assert!((value - 40.0).abs() < 1.0, "{value}"),
        other => panic!("{other:?}"),
    }
    assert!(
        tree.nodes.iter().any(|n| n.name == "Removing files"),
        "shortcuts are done"
    );
    assert!(
        find(&tree, Role::Button, "Cancel").is_none(),
        "nothing to cancel"
    );
}

fn done_script(n: usize) -> Vec<Timed> {
    scenario::uninstall_done(Os::Windows, 1000, 4000, scenario::leftovers(Os::Windows, n))
}

fn rows(tree: &lune_ui::access::SemanticTree) -> usize {
    tree.nodes
        .iter()
        .filter(|n| n.role == Role::StaticText && n.value.is_some())
        .filter(|n| n.name.contains("app-1.4") || n.name.starts_with("and "))
        .count()
}

#[test]
fn the_done_screens_list_at_most_three_rows_and_reveal_the_first() {
    let (_, _, none, _) = run_flow(Flow::Uninstall, &done_script(0), 5500);
    assert!(tree_has(&none, "Nothing was left behind."));
    assert!(find(&none, Role::Button, "Show folder").is_none());
    assert_eq!(rows(&none), 0);

    let (_, _, one, _) = run_flow(Flow::Uninstall, &done_script(1), 5500);
    assert!(tree_has(&one, "One item was in use and was left behind:"));
    assert_eq!(rows(&one), 1);
    assert!(find(&one, Role::Button, "Show folder").is_some());

    let (_, _, three, _) = run_flow(Flow::Uninstall, &done_script(3), 5500);
    assert_eq!(rows(&three), 3, "three fit");

    let (_, _, six, _) = run_flow(Flow::Uninstall, &done_script(6), 5500);
    assert!(tree_has(&six, "6 items were in use and were left behind:"));
    assert_eq!(rows(&six), 3, "two paths and 'and 4 more'");
    assert!(tree_has(&six, "and 4 more"));

    let mut s = done_script(6);
    s.push(at(5600, Step::Key(NamedKey::Tab)));
    s.push(at(5700, Step::Key(NamedKey::Enter)));
    let (_, _, _, answers) = run_flow(Flow::Uninstall, &s, 5800);
    assert!(
        matches!(
            answers.last(),
            Some(UiMsg::Choice {
                value: ChoiceValue::Reveal { index: 0 },
                ..
            })
        ),
        "{answers:?}"
    );
}

fn tree_has(tree: &lune_ui::access::SemanticTree, name: &str) -> bool {
    tree.nodes.iter().any(|n| n.name == name)
}

#[test]
fn enter_and_escape_close_every_uninstall_outcome() {
    for script in [
        done_script(0),
        done_script(1),
        scenario::uninstall_failed(Os::Windows, 1000, 4000, 9),
    ] {
        for key in [NamedKey::Enter, NamedKey::Escape] {
            let mut s = script.clone();
            s.push(at(5600, Step::Key(key)));
            let (_, _, _, answers) = run_flow(Flow::Uninstall, &s, 5700);
            assert!(
                matches!(
                    answers.last(),
                    Some(UiMsg::Choice {
                        value: ChoiceValue::Close,
                        ..
                    })
                ),
                "{key:?}: {answers:?}"
            );
        }
    }
}

#[test]
fn a_failed_uninstall_has_no_retry() {
    let (_, _, tree, _) = run_flow(
        Flow::Uninstall,
        &scenario::uninstall_failed(Os::Windows, 1000, 4000, 25),
        5500,
    );
    assert!(find(&tree, Role::Button, "Try again").is_none());
    for name in ["Copy details", "Close"] {
        assert!(find(&tree, Role::Button, name).is_some(), "{name}");
    }
    assert!(tree_has(&tree, "Lunegit is still installed."));
    assert!(tree_has(
        &tree,
        "Lunegit is still running. Close it and try again."
    ));
}

#[test]
fn the_rail_icon_dims_and_the_version_reads_removed_after_an_uninstall() {
    let (_, _, tree, _) = run_flow(Flow::Uninstall, &done_script(1), 5500);
    assert!(tree_has(&tree, "Removed"));
    assert!(
        tree.nodes
            .iter()
            .any(|n| n.name == "Step 3 of 3: Done, current")
    );
    let (_, _, before, _) = run_flow(
        Flow::Uninstall,
        &scenario::uninstall_removing(Os::Windows, 1000),
        3000,
    );
    assert!(!tree_has(&before, "Removed"));
    assert!(tree_has(&before, "Version 1.4.0"));
}

#[test]
fn a_hello_from_another_build_is_refused_and_a_message_out_of_order_is_a_protocol_error() {
    use lunepack_core::ui::{PromptKind, ProtocolError};
    use lunepack_ui_luneui::UiModel;
    let env = Env {
        os: Os::Linux,
        material: Material::Opaque,
    };
    let mut model = UiModel::new(env);
    let mut hello = scenario::install_hello(Os::Linux, "Lunegit", false);
    if let EngineMsg::Hello { build_id, .. } = &mut hello {
        *build_id = "0.0.0+ui999".to_owned();
    }
    assert_eq!(
        model.apply(&hello, Duration::ZERO),
        Err(ProtocolError::BuildIdMismatch)
    );
    assert_eq!(model.screen(), Screen::Idle, "nothing was applied");
    let prompt = EngineMsg::Prompt {
        id: 1,
        kind: PromptKind::Welcome,
    };
    assert!(matches!(
        model.apply(&prompt, Duration::ZERO),
        Err(ProtocolError::OutOfOrder(_))
    ));
}
