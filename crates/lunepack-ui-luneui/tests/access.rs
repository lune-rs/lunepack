//! The screens' accessibility tree and keyboard, with no window and no GPU: every screen's frame is
//! turned into the update AccessKit's adapters get (`tree_update`) and replayed into
//! `accesskit_consumer`, the tree the OS adapters run, so "a tree AccessKit accepts" is AccessKit's
//! own verdict. Roles, names, values and focus order are read back from it, and the keyboard drives
//! every prompt to each of its choices.

use std::time::Duration;

use accesskit_consumer::{NodeRef as ConsumerNode, Tree};
use lune_ui::access::{NodeCache, RootInfo, tree_update};
use lune_ui::input::{FrameOutput, NamedKey};
use lune_ui::motion::MotionTier;
use lune_ui::testing::FakeText;

use lunepack_core::ui::{ChoiceValue, Flow, UiMsg};
use lunepack_ui_luneui::render::{Player, RenderOptions, Step, Timed, at};
use lunepack_ui_luneui::{Env, Material, Os, scenario};

const OS: Os = Os::Linux;

fn options(flow: Flow) -> RenderOptions {
    RenderOptions {
        env: Env {
            os: OS,
            material: Material::Opaque,
        },
        tier: MotionTier::Full,
        scale: 1.0,
        flow,
    }
}

/// Plays `script` and then `keys` (one press each, 100 ms apart from `first_key`), frame by frame
/// every 10 ms to `until` ms. Returns the answers and the frame after each key press, plus the last.
fn run(
    flow: Flow,
    script: &[Timed],
    first_key: u64,
    keys: &[NamedKey],
    until: u64,
) -> (Vec<UiMsg>, Vec<FrameOutput>) {
    let mut all: Vec<Timed> = script.to_vec();
    for (i, key) in keys.iter().enumerate() {
        all.push(at(first_key + 100 * i as u64, Step::Key(*key)));
    }
    all.sort_by_key(|t| t.at);
    let mut player = Player::new(options(flow));
    let mut text = FakeText;
    let mut next = 0;
    let mut frames = Vec::new();
    let mut last = None;
    for ms in (0..=until).step_by(10) {
        let now = Duration::from_millis(ms);
        while let Some(item) = all.get(next).filter(|s| s.at <= now) {
            next += 1;
            player.play(item).expect("the script is valid");
        }
        let (_, out, _) = player.frame(&mut text, now);
        // The frame right after each key press (the press lands in the frame at its time).
        if keys
            .iter()
            .enumerate()
            .any(|(i, _)| first_key + 100 * i as u64 + 10 == ms)
        {
            frames.push(out.clone());
        }
        last = Some(out);
    }
    frames.push(last.expect("at least one frame"));
    (player.take_answers(), frames)
}

fn consumer(out: &FrameOutput) -> Tree {
    let update = tree_update(
        &out.tree,
        out.focused,
        &RootInfo {
            title: "Window".to_owned(),
            scale: 1.0,
        },
        &mut NodeCache::default(),
    );
    Tree::new(update, true)
}

/// `(role, label)` of every node under the window root, in tree order, roles by their debug name.
fn nodes(tree: &Tree) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut open = vec![tree.state().root()];
    while let Some(n) = open.pop() {
        out.push((
            format!("{:?}", n.role()),
            n.label().or_else(|| n.value()).unwrap_or_default(),
        ));
        let mut kids: Vec<ConsumerNode<'_>> = n.children().collect();
        kids.reverse();
        open.extend(kids);
    }
    out
}

fn labels(tree: &Tree, role: &str) -> Vec<String> {
    nodes(tree)
        .into_iter()
        .filter(|(r, _)| r == role)
        .map(|(_, l)| l)
        .collect()
}

fn focused_label(tree: &Tree) -> Option<String> {
    let root = tree.state().root().id();
    tree.state()
        .focus()
        .filter(|n| n.id() != root)
        .and_then(|n| n.label())
}

fn numeric(tree: &Tree, role: &str, label: &str) -> Option<f64> {
    let mut open = vec![tree.state().root()];
    while let Some(n) = open.pop() {
        if format!("{:?}", n.role()) == role && n.label().as_deref() == Some(label) {
            return n.numeric_value();
        }
        open.extend(n.children());
    }
    panic!("no {role} named {label}");
}

/// One screen: where to look at it and what its tree must hold.
struct Screen {
    name: &'static str,
    flow: Flow,
    script: Vec<Timed>,
    at: u64,
    /// The buttons, as `(label)`, sorted; every screen has its caption buttons too.
    buttons: Vec<&'static str>,
    /// Progress bars as `(label, value)`; `None` is indeterminate.
    bars: Vec<(&'static str, Option<f64>)>,
    /// The dialog's label.
    window: &'static str,
}

fn screens() -> Vec<Screen> {
    let both = ["Minimize", "Close"];
    let min = ["Minimize"];
    let close = ["Close"];
    let with = |base: &[&'static str], extra: &[&'static str]| -> Vec<&'static str> {
        let mut v: Vec<&'static str> = base.iter().chain(extra).copied().collect();
        v.sort_unstable();
        v
    };
    vec![
        Screen {
            name: "install welcome",
            flow: Flow::Install,
            script: scenario::install_welcome(OS, scenario::APP_NAME, true),
            at: 600,
            buttons: with(&both, &["Cancel", "Install"]),
            bars: vec![],
            window: "Install Lunegit",
        },
        Screen {
            name: "installing",
            flow: Flow::Install,
            script: scenario::install_running(OS, 1000),
            at: 3000,
            buttons: with(&both, &["Cancel"]),
            bars: vec![("Installation progress", Some(67.0))],
            window: "Install Lunegit",
        },
        Screen {
            name: "install done",
            flow: Flow::Install,
            script: scenario::install_done(OS, 1000, 4000),
            at: 5500,
            buttons: with(&both, &["Finish"]),
            bars: vec![("Installation complete", Some(100.0))],
            window: "Install Lunegit",
        },
        Screen {
            name: "install failed",
            flow: Flow::Install,
            script: scenario::install_failed(OS, 1000, 4000, 9),
            at: 5500,
            buttons: with(&both, &["Close", "Copy details", "Try again"]),
            bars: vec![("Install failed", Some(67.0))],
            window: "Install Lunegit",
        },
        Screen {
            name: "update waiting",
            flow: Flow::Update,
            script: scenario::update_waiting(),
            at: 1000,
            buttons: with(&min, &[]),
            bars: vec![("Waiting for the app to close", None)],
            window: "Update Lunegit",
        },
        Screen {
            name: "update applying",
            flow: Flow::Update,
            script: scenario::update_applying(1000, 74),
            at: 2500,
            buttons: with(&min, &[]),
            bars: vec![("Updating", Some(74.0))],
            window: "Update Lunegit",
        },
        Screen {
            name: "update starting",
            flow: Flow::Update,
            script: scenario::update_starting(1000, 2000),
            at: 3500,
            buttons: with(&min, &[]),
            bars: vec![("Starting the new version", Some(100.0))],
            window: "Update Lunegit",
        },
        Screen {
            name: "update rolled back",
            flow: Flow::Update,
            script: scenario::update_rolled_back(1000, 2000, 3000),
            at: 4500,
            buttons: with(&min, &["OK"]),
            bars: vec![("Update undone", Some(100.0))],
            window: "Update Lunegit",
        },
        Screen {
            name: "update failed",
            flow: Flow::Update,
            script: scenario::update_failed(1000, 3000, 9),
            at: 4500,
            buttons: with(&min, &["Close", "Copy details"]),
            bars: vec![("Update failed", Some(74.0))],
            window: "Update Lunegit",
        },
        Screen {
            name: "uninstall confirm",
            flow: Flow::Uninstall,
            script: scenario::uninstall_confirm(OS),
            at: 600,
            buttons: with(&close, &["Cancel", "Uninstall"]),
            bars: vec![],
            window: "Uninstall Lunegit",
        },
        Screen {
            name: "uninstall removing",
            flow: Flow::Uninstall,
            script: scenario::uninstall_removing(OS, 1000),
            at: 3000,
            buttons: with(&close, &[]),
            bars: vec![("Removing", Some(40.0))],
            window: "Uninstall Lunegit",
        },
        Screen {
            name: "uninstall done, nothing left",
            flow: Flow::Uninstall,
            script: scenario::uninstall_done(OS, 1000, 4000, vec![]),
            at: 5500,
            buttons: with(&close, &["Close"]),
            bars: vec![],
            window: "Uninstall Lunegit",
        },
        Screen {
            name: "uninstall done, leftovers",
            flow: Flow::Uninstall,
            script: scenario::uninstall_done(OS, 1000, 4000, scenario::leftovers(OS, 1)),
            at: 5500,
            buttons: with(&close, &["Close", "Show folder"]),
            bars: vec![],
            window: "Uninstall Lunegit",
        },
        Screen {
            name: "uninstall failed",
            flow: Flow::Uninstall,
            script: scenario::uninstall_failed(OS, 1000, 4000, 9),
            at: 5500,
            buttons: with(&close, &["Close", "Copy details"]),
            bars: vec![("Uninstall failed", Some(40.0))],
            window: "Uninstall Lunegit",
        },
    ]
}

#[test]
fn every_screen_has_the_roles_names_and_values_a_screen_reader_needs() {
    for s in screens() {
        let (_, frames) = run(s.flow, &s.script, s.at + 1000, &[], s.at);
        let tree = consumer(frames.last().expect("a frame"));
        let all = nodes(&tree);

        let dialogs = labels(&tree, "Dialog");
        assert_eq!(
            dialogs,
            vec![s.window.to_owned()],
            "{}: the window is one named dialog",
            s.name
        );

        let mut buttons = labels(&tree, "Button");
        buttons.sort_unstable();
        assert_eq!(buttons, s.buttons, "{}: the buttons", s.name);

        let bars = labels(&tree, "ProgressIndicator");
        let mut want: Vec<&str> = s.bars.iter().map(|(n, _)| *n).collect();
        want.sort_unstable();
        let mut got: Vec<&str> = bars.iter().map(String::as_str).collect();
        got.sort_unstable();
        assert_eq!(got, want, "{}: the progress bars", s.name);
        for (name, value) in &s.bars {
            let v = numeric(&tree, "ProgressIndicator", name);
            match value {
                Some(expect) => {
                    let v = v.unwrap_or_else(|| panic!("{}: {name} has no value", s.name));
                    assert!(
                        (v - expect).abs() < 1.5,
                        "{}: {name} is {v}, want {expect}",
                        s.name
                    );
                }
                None => assert_eq!(v, None, "{}: {name} is indeterminate", s.name),
            }
        }

        // Every control that can be operated has a name.
        for (role, label) in &all {
            if matches!(
                role.as_str(),
                "Button" | "CheckBox" | "ProgressIndicator" | "Dialog" | "Image"
            ) {
                assert!(!label.trim().is_empty(), "{}: a nameless {role}", s.name);
            }
        }
        // The rail names the app and the step the screen is on.
        let step = |n: &str| all.iter().any(|(_, l)| l.starts_with(n));
        if s.flow != Flow::Update {
            assert!(
                step("Step 1 of 3"),
                "{}: the rail's steps are named",
                s.name
            );
        }
        assert!(
            all.iter().any(|(r, l)| r == "Image" && l == "Lunegit"),
            "{}: the app icon is named",
            s.name
        );
    }
}

#[test]
fn the_done_screens_checkbox_is_named_and_checked() {
    let s = scenario::install_done(OS, 1000, 4000);
    let (_, frames) = run(Flow::Install, &s, 6000, &[], 5500);
    let tree = consumer(frames.last().unwrap());
    assert_eq!(
        labels(&tree, "CheckBox"),
        vec!["Open Lunegit now".to_owned()]
    );
}

/// The Tab order of each screen that has controls, as the labels the focus visits, and that one more
/// Tab wraps to the first.
#[test]
fn tab_order_is_the_visual_order_on_every_screen_with_controls() {
    /// A screen, its flow and script, when to look at it and the labels Tab visits in order.
    type TabCase<'a> = (&'a str, Flow, Vec<Timed>, u64, Vec<&'a str>);
    let cases: Vec<TabCase<'_>> = vec![
        (
            "install welcome",
            Flow::Install,
            scenario::install_welcome(OS, scenario::APP_NAME, true),
            600,
            vec!["Cancel", "Install"],
        ),
        (
            "installing",
            Flow::Install,
            scenario::install_running(OS, 1000),
            3000,
            vec!["Cancel"],
        ),
        (
            "install done",
            Flow::Install,
            scenario::install_done(OS, 1000, 4000),
            5500,
            vec!["Open Lunegit now", "Finish"],
        ),
        (
            "install failed",
            Flow::Install,
            scenario::install_failed(OS, 1000, 4000, 9),
            5500,
            vec!["Copy details", "Close", "Try again"],
        ),
        (
            "update rolled back",
            Flow::Update,
            scenario::update_rolled_back(1000, 2000, 3000),
            4500,
            vec!["OK"],
        ),
        (
            "update failed",
            Flow::Update,
            scenario::update_failed(1000, 3000, 9),
            4500,
            vec!["Copy details", "Close"],
        ),
        (
            "uninstall confirm",
            Flow::Uninstall,
            scenario::uninstall_confirm(OS),
            600,
            vec!["Cancel", "Uninstall"],
        ),
        (
            "uninstall done",
            Flow::Uninstall,
            scenario::uninstall_done(OS, 1000, 4000, scenario::leftovers(OS, 1)),
            5500,
            vec!["Show folder", "Close"],
        ),
        (
            "uninstall failed",
            Flow::Uninstall,
            scenario::uninstall_failed(OS, 1000, 4000, 9),
            5500,
            vec!["Copy details", "Close"],
        ),
    ];
    for (name, flow, script, at_ms, order) in cases {
        let mut keys = vec![NamedKey::Tab; order.len() + 1];
        // One more Tab than controls: the last wraps to the first.
        let (_, frames) = run(
            flow,
            &script,
            at_ms + 100,
            &keys,
            at_ms + 100 * (order.len() as u64 + 2),
        );
        let visited: Vec<Option<String>> = frames[..order.len() + 1]
            .iter()
            .map(|f| focused_label(&consumer(f)))
            .collect();
        let want: Vec<Option<String>> = order
            .iter()
            .map(|l| Some((*l).to_owned()))
            .chain(std::iter::once(Some(order[0].to_owned())))
            .collect();
        assert_eq!(visited, want, "{name}: the focus order");
        keys.clear();
    }
}

fn choice(value: ChoiceValue) -> impl Fn(&UiMsg) -> bool {
    move |m| matches!(m, UiMsg::Choice { value: v, .. } if *v == value)
}

/// Keys that drive a prompt to one of its choices, and the choice.
struct Drive {
    name: &'static str,
    flow: Flow,
    script: Vec<Timed>,
    at: u64,
    keys: Vec<NamedKey>,
    /// Checks the last answer.
    check: Box<dyn Fn(&UiMsg) -> bool>,
}

fn drive(
    name: &'static str,
    flow: Flow,
    script: Vec<Timed>,
    at: u64,
    keys: &[NamedKey],
    check: impl Fn(&UiMsg) -> bool + 'static,
) -> Drive {
    Drive {
        name,
        flow,
        script,
        at,
        keys: keys.to_vec(),
        check: Box::new(check),
    }
}

#[test]
fn the_keyboard_drives_every_prompt_to_every_choice() {
    use NamedKey::{Enter, Escape, Space, Tab};
    let cancel_msg = |m: &UiMsg| matches!(m, UiMsg::Cancel);
    let welcome = || scenario::install_welcome(OS, scenario::APP_NAME, true);
    let failed = || scenario::install_failed(OS, 1000, 4000, 9);
    let uconfirm = || scenario::uninstall_confirm(OS);
    let udone = || scenario::uninstall_done(OS, 1000, 4000, scenario::leftovers(OS, 1));
    let cases = vec![
        drive(
            "welcome: Enter proceeds",
            Flow::Install,
            welcome(),
            600,
            &[Enter],
            choice(ChoiceValue::Proceed),
        ),
        drive(
            "welcome: Esc cancels",
            Flow::Install,
            welcome(),
            600,
            &[Escape],
            choice(ChoiceValue::Cancel),
        ),
        drive(
            "welcome: Tab, Enter cancels",
            Flow::Install,
            welcome(),
            600,
            &[Tab, Enter],
            choice(ChoiceValue::Cancel),
        ),
        drive(
            "welcome: Tab, Tab, Space installs",
            Flow::Install,
            welcome(),
            600,
            &[Tab, Tab, Space],
            choice(ChoiceValue::Proceed),
        ),
        drive(
            "installing: Tab, Enter cancels",
            Flow::Install,
            scenario::install_running(OS, 1000),
            3000,
            &[Tab, Enter],
            cancel_msg,
        ),
        drive(
            "done: Enter finishes and launches",
            Flow::Install,
            scenario::install_done(OS, 1000, 4000),
            5500,
            &[Enter],
            choice(ChoiceValue::Finish { launch: true }),
        ),
        drive(
            "done: Tab, Space, Tab, Enter finishes without",
            Flow::Install,
            scenario::install_done(OS, 1000, 4000),
            5500,
            &[Tab, Space, Tab, Enter],
            choice(ChoiceValue::Finish { launch: false }),
        ),
        drive(
            "failed: Enter retries",
            Flow::Install,
            failed(),
            5500,
            &[Enter],
            choice(ChoiceValue::Retry),
        ),
        drive(
            "failed: Esc closes",
            Flow::Install,
            failed(),
            5500,
            &[Escape],
            choice(ChoiceValue::Close),
        ),
        drive(
            "failed: Tab, Tab, Enter closes",
            Flow::Install,
            failed(),
            5500,
            &[Tab, Tab, Enter],
            choice(ChoiceValue::Close),
        ),
        drive(
            "failed: Tab x3, Enter retries",
            Flow::Install,
            failed(),
            5500,
            &[Tab, Tab, Tab, Enter],
            choice(ChoiceValue::Retry),
        ),
        drive(
            "rolled back: Enter acknowledges",
            Flow::Update,
            scenario::update_rolled_back(1000, 2000, 3000),
            4500,
            &[Enter],
            choice(ChoiceValue::Acknowledge),
        ),
        drive(
            "rolled back: Tab, Space acknowledges",
            Flow::Update,
            scenario::update_rolled_back(1000, 2000, 3000),
            4500,
            &[Tab, Space],
            choice(ChoiceValue::Acknowledge),
        ),
        drive(
            "update failed: Enter closes",
            Flow::Update,
            scenario::update_failed(1000, 3000, 9),
            4500,
            &[Enter],
            choice(ChoiceValue::Close),
        ),
        drive(
            "update failed: Esc closes",
            Flow::Update,
            scenario::update_failed(1000, 3000, 9),
            4500,
            &[Escape],
            choice(ChoiceValue::Close),
        ),
        drive(
            "confirm: Enter uninstalls",
            Flow::Uninstall,
            uconfirm(),
            600,
            &[Enter],
            choice(ChoiceValue::Proceed),
        ),
        drive(
            "confirm: Esc cancels",
            Flow::Uninstall,
            uconfirm(),
            600,
            &[Escape],
            choice(ChoiceValue::Cancel),
        ),
        drive(
            "confirm: Tab, Tab, Enter uninstalls",
            Flow::Uninstall,
            uconfirm(),
            600,
            &[Tab, Tab, Enter],
            choice(ChoiceValue::Proceed),
        ),
        drive(
            "confirm: Tab, Enter cancels",
            Flow::Uninstall,
            uconfirm(),
            600,
            &[Tab, Enter],
            choice(ChoiceValue::Cancel),
        ),
        drive(
            "done: Enter closes",
            Flow::Uninstall,
            udone(),
            5500,
            &[Enter],
            choice(ChoiceValue::Close),
        ),
        drive(
            "done: Esc closes",
            Flow::Uninstall,
            udone(),
            5500,
            &[Escape],
            choice(ChoiceValue::Close),
        ),
        drive(
            "done: Tab, Enter shows the folder",
            Flow::Uninstall,
            udone(),
            5500,
            &[Tab, Enter],
            choice(ChoiceValue::Reveal { index: 0 }),
        ),
        drive(
            "done: Tab, Tab, Enter closes",
            Flow::Uninstall,
            udone(),
            5500,
            &[Tab, Tab, Enter],
            choice(ChoiceValue::Close),
        ),
        drive(
            "uninstall failed: Enter closes",
            Flow::Uninstall,
            scenario::uninstall_failed(OS, 1000, 4000, 9),
            5500,
            &[Enter],
            choice(ChoiceValue::Close),
        ),
        drive(
            "uninstall failed: Esc closes",
            Flow::Uninstall,
            scenario::uninstall_failed(OS, 1000, 4000, 9),
            5500,
            &[Escape],
            choice(ChoiceValue::Close),
        ),
    ];
    for case in cases {
        let (answers, _) = run(
            case.flow,
            &case.script,
            case.at + 100,
            &case.keys,
            case.at + 100 * (case.keys.len() as u64 + 2),
        );
        // The scripted steps of the scenario (a Choose that moved the flow on) answer too; the last
        // answer is the one the keys produced.
        let last = answers
            .last()
            .unwrap_or_else(|| panic!("{}: no answer", case.name));
        assert!((case.check)(last), "{}: answered {last:?}", case.name);
    }
}

#[test]
fn no_key_answers_a_screen_that_has_nothing_to_answer() {
    // While an update runs there is nothing to cancel or confirm.
    for script in [
        scenario::update_waiting(),
        scenario::update_applying(1000, 74),
        scenario::update_starting(1000, 2000),
    ] {
        let (answers, _) = run(
            Flow::Update,
            &script,
            4000,
            &[
                NamedKey::Enter,
                NamedKey::Escape,
                NamedKey::Tab,
                NamedKey::Space,
            ],
            4600,
        );
        assert!(answers.is_empty(), "{answers:?}");
    }
}
