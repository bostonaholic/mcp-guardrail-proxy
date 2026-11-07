//! What each poll of the log does, mirrored from `specs/DashboardWatch.tla`. Pure: no I/O, no UI.

/// Whether the log's history has loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchPhase {
    /// No read has worked yet, so the next one that does returns lines from before launch.
    LoadingHistory,
    /// A read has worked, so later lines are new.
    Live,
}

/// What a poll must do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollActions {
    /// The screen is out of date.
    pub publish: bool,
    /// Blocked calls in this poll are new, so they may raise a notification.
    pub may_alert: bool,
}

/// Remembers what is on screen, so a poll publishes exactly when something changed.
#[derive(Clone, Debug)]
pub struct Watch {
    phase: WatchPhase,
    shown_revision: u64,
    shown_error: Option<String>,
}

impl Watch {
    /// A watch before the first read, with an empty dashboard on screen.
    pub fn new() -> Self {
        Self {
            phase: WatchPhase::LoadingHistory,
            shown_revision: 0,
            shown_error: None,
        }
    }

    /// Records a poll that left the dashboard at `revision` and ended with `error`.
    pub fn after_poll(&mut self, revision: u64, error: Option<&str>) -> PollActions {
        let publish = revision != self.shown_revision || error != self.shown_error.as_deref();
        self.shown_revision = revision;
        self.shown_error = error.map(str::to_string);
        let read_worked = error.is_none();
        let may_alert = read_worked && self.phase == WatchPhase::Live;
        if read_worked {
            self.phase = WatchPhase::Live;
        }
        PollActions { publish, may_alert }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_graph::{SpecGraph, Step, tla_bool};

    /// The watch, the dashboard's revision, and what the last poll said.
    #[derive(Clone)]
    struct Walked {
        watch: Watch,
        revision: u64,
        actions: PollActions,
    }

    fn apply(walked: &mut Walked, step: &Step<'_>) {
        let error = match step.action {
            "PollFails" => Some(step.to["error"].as_str()),
            "PollQuiet" => None,
            "PollNewLines" => {
                walked.revision += 1;
                None
            }
            other => panic!("unknown action {other}"),
        };
        walked.actions = walked.watch.after_poll(walked.revision, error);
    }

    #[test]
    fn watch_matches_every_edge_of_the_spec() {
        let graph = SpecGraph::parse(include_str!("../../specs/graphs/DashboardWatch.graph"));
        let walked = graph.walk(
            Walked {
                watch: Watch::new(),
                revision: 0,
                actions: PollActions {
                    publish: false,
                    may_alert: false,
                },
            },
            |walked| {
                let shown_error = walked.watch.shown_error.as_deref().unwrap_or("None");
                vec![
                    ("phase", format!("{:?}", walked.watch.phase)),
                    ("shownError", shown_error.to_string()),
                    ("shownRevision", walked.watch.shown_revision.to_string()),
                    ("published", tla_bool(walked.actions.publish)),
                    ("mayAlert", tla_bool(walked.actions.may_alert)),
                ]
            },
            apply,
        );
        assert!(walked > 0);
    }

    #[test]
    fn an_error_from_the_launch_read_clears_when_the_file_recovers() {
        let mut watch = Watch::new();
        watch.after_poll(0, Some("permission denied"));
        let recovered = watch.after_poll(0, None);
        assert!(recovered.publish, "the banner must go away");
    }

    #[test]
    fn a_malformed_line_alone_reaches_the_screen() {
        let mut watch = Watch::new();
        watch.after_poll(0, None);
        assert!(watch.after_poll(1, None).publish);
    }

    #[test]
    fn history_after_a_failed_launch_read_stays_silent() {
        let mut watch = Watch::new();
        watch.after_poll(0, Some("permission denied"));
        assert!(!watch.after_poll(5, None).may_alert);
        assert!(watch.after_poll(6, None).may_alert);
    }
}
