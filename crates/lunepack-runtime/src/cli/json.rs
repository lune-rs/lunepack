//! The final objects of the app-facing commands, as schema-1 JSON Lines and as one human line
//! (C4 Output, M5-D12). Strings come only from signed documents (versions), closed sets and the
//! build; an error's own text is never used.
//!
//! Progress events are the runtime's ([`crate::events::to_json_line`]); the objects here are the
//! two kinds that end a command: `result` and `error`.

use std::fmt::Write as _;

use lunepack::{LifecycleEvent, PublisherOutcome, Version};

use crate::events::{head, json_str, json_version};
use crate::modes::Kind;

/// What `check` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSummary {
    /// The new version.
    pub version: Version,
    /// The most bytes a download fetches.
    pub download_size_max: u64,
    /// Whether expiry and key windows were checked (false under an implausible clock).
    pub time_checked: bool,
}

/// The command-specific members of a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// `check`: the update, or none, and whether this check adopted the running bundle (M8-D9;
    /// the `adopted` member is written only when it did, so the object is unchanged otherwise).
    Check {
        /// The update, or none.
        update: Option<UpdateSummary>,
        /// The check adopted the running bundle before it checked.
        adopted: bool,
    },
    /// `download`: the version staged, or none when the channel offers nothing new, and what the
    /// publisher check reported when it let the version through (M9-D9; the `publisher` member is
    /// written only then, so the object is unchanged otherwise).
    Download {
        /// The staged version, or none.
        version: Option<Version>,
        /// The publisher check's finding (a closed code), when there was one.
        publisher: Option<PublisherOutcome>,
    },
    /// `startup`: the events delivered, whether the app goes on, whether its version is still
    /// pending its health check.
    Startup {
        /// Lifecycle events for this version, oldest first.
        events: Vec<LifecycleEvent>,
        /// `true` to exit: this version was rolled back and the previous one was started.
        exit: bool,
        /// Whether the version still waits for `confirm`.
        pending: bool,
    },
    /// `confirm`: `confirmed` or `nothing_pending`.
    Confirm(&'static str),
    /// `apply-and-restart`: the version the detached applier was started to apply.
    ApplyAndRestart(Version),
    /// `repair`: the update service's registration was re-created (M10-D13).
    Repair,
}

fn event(out: &mut String, e: &LifecycleEvent) {
    match e {
        LifecycleEvent::Installed { version } => {
            out.push_str("{\"kind\":\"installed\",\"version\":");
            json_str(out, &version.to_string());
        }
        LifecycleEvent::Updated { from, to } => {
            out.push_str("{\"kind\":\"updated\",\"from\":");
            json_str(out, &from.to_string());
            out.push_str(",\"to\":");
            json_str(out, &to.to_string());
        }
        LifecycleEvent::FirstRun { version } => {
            out.push_str("{\"kind\":\"first_run\",\"version\":");
            json_str(out, &version.to_string());
        }
    }
    out.push('}');
}

/// The `result` object of `command`, run from the tree of `tree_version`.
pub fn result_line(command: &str, tree_version: &Version, body: &Body) -> String {
    let mut out = String::with_capacity(160);
    head(&mut out, "result");
    out.push_str(",\"command\":");
    json_str(&mut out, command);
    out.push_str(",\"tree_version\":");
    json_version(&mut out, Some(tree_version));
    match body {
        Body::Check { update, adopted } => {
            match update {
                None => out.push_str(",\"update\":null"),
                Some(u) => {
                    out.push_str(",\"update\":{\"version\":");
                    json_str(&mut out, &u.version.to_string());
                    let _ = write!(
                        out,
                        ",\"download_size_max\":{},\"time_checked\":{}}}",
                        u.download_size_max, u.time_checked
                    );
                }
            }
            if *adopted {
                out.push_str(",\"adopted\":true");
            }
        }
        Body::Download { version, publisher } => {
            out.push_str(",\"version\":");
            json_version(&mut out, version.as_ref());
            let _ = write!(out, ",\"staged\":{}", version.is_some());
            if let Some(found) = publisher {
                out.push_str(",\"publisher\":");
                json_str(&mut out, found.code());
            }
        }
        Body::Startup {
            events,
            exit,
            pending,
        } => {
            out.push_str(",\"events\":[");
            for (i, e) in events.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                event(&mut out, e);
            }
            out.push_str("],\"action\":");
            json_str(&mut out, if *exit { "exit" } else { "continue" });
            let _ = write!(out, ",\"pending\":{pending}");
        }
        Body::Confirm(outcome) => {
            out.push_str(",\"outcome\":");
            json_str(&mut out, outcome);
        }
        Body::ApplyAndRestart(version) => {
            out.push_str(",\"version\":");
            json_str(&mut out, &version.to_string());
            out.push_str(",\"scheduled\":true");
        }
        Body::Repair => out.push_str(",\"repaired\":true"),
    }
    out.push('}');
    out
}

/// The `error` object. `command` and `tree_version` are null when not known (a usage error, a
/// tree with no update config).
pub fn error_line(command: Option<&str>, tree_version: Option<&Version>, kind: Kind) -> String {
    let mut out = String::with_capacity(128);
    head(&mut out, "error");
    out.push_str(",\"command\":");
    match command {
        Some(c) => json_str(&mut out, c),
        None => out.push_str("null"),
    }
    out.push_str(",\"tree_version\":");
    json_version(&mut out, tree_version);
    out.push_str(",\"kind\":");
    json_str(&mut out, kind.name());
    let _ = write!(out, ",\"exit_code\":{}", kind.code());
    if let Some(reason) = kind.reason() {
        out.push_str(",\"reason\":");
        json_str(&mut out, reason);
    }
    out.push('}');
    out
}

/// The one human line of a result.
pub fn human_result(command: &str, body: &Body) -> String {
    match body {
        Body::Check { update, adopted } => {
            let found = match update {
                None => format!("{command}: no update"),
                Some(u) => format!("{command}: update {} is available", u.version),
            };
            if *adopted {
                format!("{found} (adopted this copy as the install)")
            } else {
                found
            }
        }
        Body::Download { version: None, .. } => format!("{command}: no update"),
        Body::Download {
            version: Some(v),
            publisher: None,
        } => format!("{command}: staged {v}"),
        Body::Download {
            version: Some(v),
            publisher: Some(found),
        } => format!("{command}: staged {v} (publisher: {})", found.code()),
        Body::Startup {
            events,
            exit,
            pending,
        } => format!(
            "{command}: {}, {} event(s){}",
            if *exit { "exit" } else { "continue" },
            events.len(),
            if *pending { ", pending" } else { "" }
        ),
        Body::Confirm(outcome) => format!("{command}: {outcome}"),
        Body::ApplyAndRestart(v) => format!("{command}: scheduled {v}"),
        Body::Repair => format!("{command}: repaired"),
    }
}

/// The one human line of an error.
pub fn human_error(command: Option<&str>, kind: Kind) -> String {
    let reason = kind.reason().map(|r| format!(", {r}")).unwrap_or_default();
    match command {
        Some(c) => format!("{c}: error: {} (exit {}{reason})", kind.name(), kind.code()),
        None => format!("error: {} (exit {}{reason})", kind.name(), kind.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    /// The goldens of the final objects, one per line: a result of each command (with and without
    /// its optional parts) and the error of every kind. `tests/golden/objects.jsonl` is the
    /// committed copy; this test and the integration tests (which run the binary) both read it.
    fn objects() -> String {
        let tree = v("1.0.0");
        let mut lines = vec![
            result_line(
                "check",
                &tree,
                &Body::Check {
                    update: None,
                    adopted: false,
                },
            ),
            result_line(
                "check",
                &tree,
                &Body::Check {
                    update: Some(UpdateSummary {
                        version: v("1.1.0"),
                        download_size_max: 123_456,
                        time_checked: true,
                    }),
                    adopted: false,
                },
            ),
            result_line(
                "check",
                &tree,
                &Body::Check {
                    update: Some(UpdateSummary {
                        version: v("2.0.0-rc.1"),
                        download_size_max: 0,
                        time_checked: false,
                    }),
                    adopted: false,
                },
            ),
            result_line(
                "download",
                &tree,
                &Body::Download {
                    version: Some(v("1.1.0")),
                    publisher: None,
                },
            ),
            result_line(
                "download",
                &tree,
                &Body::Download {
                    version: None,
                    publisher: None,
                },
            ),
            result_line(
                "startup",
                &tree,
                &Body::Startup {
                    events: Vec::new(),
                    exit: false,
                    pending: false,
                },
            ),
            result_line(
                "startup",
                &tree,
                &Body::Startup {
                    events: vec![
                        LifecycleEvent::Installed {
                            version: v("1.0.0"),
                        },
                        LifecycleEvent::Updated {
                            from: v("1.0.0"),
                            to: v("1.1.0"),
                        },
                        LifecycleEvent::FirstRun {
                            version: v("1.1.0"),
                        },
                    ],
                    exit: false,
                    pending: true,
                },
            ),
            result_line(
                "startup",
                &tree,
                &Body::Startup {
                    events: Vec::new(),
                    exit: true,
                    pending: false,
                },
            ),
            result_line("confirm", &tree, &Body::Confirm("confirmed")),
            result_line("confirm", &tree, &Body::Confirm("nothing_pending")),
            error_line(None, None, Kind::Usage),
        ];
        for kind in Kind::ALL.into_iter().filter(|k| *k != Kind::Ok) {
            lines.push(error_line(Some("check"), Some(&tree), kind));
        }

        // apply-and-restart (step 13): its result and the two errors a caller acts on.
        lines.push(result_line(
            "apply-and-restart",
            &tree,
            &Body::ApplyAndRestart(v("1.1.0")),
        ));
        lines.push(error_line(
            Some("apply-and-restart"),
            Some(&tree),
            Kind::NothingStaged,
        ));
        lines.push(error_line(
            Some("apply-and-restart"),
            Some(&tree),
            Kind::UnexpectedVersion,
        ));
        // The other reasons of exit 28 (the representative in the loop above carries the first).
        // Last, so the lines the integration tests address by number keep their places.
        for place in crate::modes::Place::ALL.into_iter().skip(1) {
            lines.push(error_line(
                Some("check"),
                Some(&tree),
                Kind::UnsupportedLocation(place),
            ));
        }
        // A check that adopted the running bundle (M8-D9), with and without an update after it.
        lines.push(result_line(
            "check",
            &tree,
            &Body::Check {
                update: None,
                adopted: true,
            },
        ));
        lines.push(result_line(
            "check",
            &tree,
            &Body::Check {
                update: Some(UpdateSummary {
                    version: v("1.1.0"),
                    download_size_max: 123_456,
                    time_checked: true,
                }),
                adopted: true,
            },
        ));
        // The other reasons of exit 29 (the representative in the loop above carries the first),
        // and a download the publisher check let through with a finding (M9-D9).
        for reason in crate::modes::PUBLISHER_REASONS.into_iter().skip(1) {
            lines.push(error_line(
                Some("download"),
                Some(&tree),
                Kind::PublisherMismatch(reason),
            ));
        }
        lines.push(result_line(
            "download",
            &tree,
            &Body::Download {
                version: Some(v("1.1.0")),
                publisher: Some(PublisherOutcome::InstalledUnsigned),
            },
        ));
        // The other reasons of exit 32 (the representative in the loop above carries the first),
        // and the result of `repair` (M10 step 18).
        for why in crate::modes::ServiceWhy::ALL.into_iter().skip(1) {
            lines.push(error_line(
                Some("check"),
                Some(&tree),
                Kind::ServiceUnavailable(why),
            ));
        }
        lines.push(result_line("repair", &tree, &Body::Repair));
        lines.push(error_line(
            Some("repair"),
            Some(&tree),
            Kind::ElevationRequired,
        ));
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }

    /// One line per kind of event the runtime writes while a command runs.
    fn events() -> String {
        use crate::events::{Event, Reason, Warning, to_json_line};
        use lunepack::{FileProgress, Phase, Progress, RelPath, Source};
        let mut events = vec![
            Event::Progress(Progress {
                phase: Phase::Scan,
                done: 0,
                total: 0,
                file: None,
            }),
            Event::Progress(Progress {
                phase: Phase::Download,
                done: 10,
                total: 100,
                file: None,
            }),
        ];
        for source in [Source::Unchanged, Source::Range, Source::FullPack] {
            events.push(Event::Progress(Progress {
                phase: Phase::Stage,
                done: 7,
                total: 70,
                file: Some(FileProgress {
                    path: RelPath::parse("bin/app").expect("path"),
                    done: 3,
                    total: 9,
                    source,
                }),
            }));
        }
        for phase in [
            Phase::Check,
            Phase::Install,
            Phase::Wait,
            Phase::Apply,
            Phase::Launch,
            Phase::Confirm,
            Phase::Uninstall,
        ] {
            events.push(Event::phase(phase, Some(&v("1.1.0"))));
        }
        for reason in [Reason::Crashed, Reason::Timeout, Reason::SpawnFailed] {
            events.push(Event::Phase {
                phase: Phase::Rollback,
                version: Some(v("1.1.0")),
                reason: Some(reason),
            });
        }
        events.push(Event::warning(Warning::GcInUse, Some(&v("1.0.0"))));
        events.push(Event::warning(Warning::SinkDropped, None));
        events.push(Event::UiStopped {
            reason: "stalled",
            exit_code: None,
        });
        events.push(Event::UiStopped {
            reason: "exited",
            exit_code: Some(11),
        });
        events.push(Event::Result {
            command: "apply",
            tree_version: Some(v("1.0.0")),
            outcome: "confirmed",
            version: Some(v("1.1.0")),
        });
        events.push(Event::Error {
            command: "install",
            tree_version: None,
            kind: "integration",
            exit_code: 24,
            reason: None,
        });
        events.push(Event::Error {
            command: "install",
            tree_version: None,
            kind: "unsupported_location",
            exit_code: 28,
            reason: Some("other_volume"),
        });
        // The proof of a bundle the check adopts (M8-D9).
        events.push(Event::Progress(Progress {
            phase: Phase::Adopt,
            done: 512,
            total: 4096,
            file: None,
        }));
        let mut text: Vec<String> = events.iter().map(to_json_line).collect();
        text.push(String::new());
        text.join("\n")
    }

    #[test]
    fn the_events_match_the_golden() {
        let golden = include_str!("../../tests/golden/events.jsonl");
        assert_eq!(events(), golden);
    }

    #[test]
    fn the_final_objects_match_the_golden() {
        let golden = include_str!("../../tests/golden/objects.jsonl");
        assert_eq!(objects(), golden);
    }

    #[test]
    fn human_lines_name_no_value_of_the_environment() {
        let line = human_result(
            "check",
            &Body::Check {
                update: Some(UpdateSummary {
                    version: v("1.1.0"),
                    download_size_max: 1,
                    time_checked: true,
                }),
                adopted: false,
            },
        );
        assert_eq!(line, "check: update 1.1.0 is available");
        assert_eq!(
            human_error(Some("download"), Kind::UnexpectedVersion),
            "download: error: unexpected_version (exit 15)"
        );
        assert_eq!(human_error(None, Kind::Usage), "error: usage (exit 2)");
        assert_eq!(
            human_error(
                Some("download"),
                Kind::PublisherMismatch(PublisherOutcome::Different)
            ),
            "download: error: publisher_mismatch (exit 29, different)"
        );
        assert_eq!(
            human_result(
                "download",
                &Body::Download {
                    version: Some(v("1.1.0")),
                    publisher: Some(PublisherOutcome::CandidateUnsigned),
                }
            ),
            "download: staged 1.1.0 (publisher: candidate_unsigned)"
        );
        assert_eq!(
            human_error(
                Some("check"),
                Kind::UnsupportedLocation(crate::modes::Place::ReadOnly)
            ),
            "check: error: unsupported_location (exit 28, read_only)"
        );
        assert_eq!(
            human_error(
                Some("check"),
                Kind::ServiceUnavailable(crate::modes::ServiceWhy::Disabled)
            ),
            "check: error: service_unavailable (exit 32, disabled)"
        );
        assert_eq!(human_result("repair", &Body::Repair), "repair: repaired");
    }
}
