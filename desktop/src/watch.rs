//! What each poll of the log does, and how many blocked calls are unread, mirrored from
//! `specs/DashboardWatch.tla`. Pure: no I/O, no UI.

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

/// What a request to mark blocked calls read must do. A request that moves nothing asks for
/// nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkActions {
    /// The unread count on screen is out of date.
    pub publish: bool,
    /// The read mark to save, so the next launch starts from it.
    pub save: Option<u64>,
}

/// Remembers what is on screen, so a poll publishes exactly when something changed, and
/// remembers the read mark: how many of the log's blocked calls the person has marked read.
#[derive(Clone, Debug)]
pub struct Watch {
    phase: WatchPhase,
    shown_revision: u64,
    shown_error: Option<String>,
    shown_unread: u64,
    /// The read mark an earlier run saved for this log. The history read settles it.
    saved_read: u64,
    /// The blocked calls the dashboard had counted at the last read that worked.
    blocked: u64,
    read_blocked: u64,
}

impl Watch {
    /// A watch before the first read, with an empty dashboard on screen. `saved_read` is the
    /// read mark an earlier run saved for this log, or 0 for none.
    pub fn new(saved_read: u64) -> Self {
        Self {
            phase: WatchPhase::LoadingHistory,
            shown_revision: 0,
            shown_error: None,
            shown_unread: 0,
            saved_read,
            blocked: 0,
            read_blocked: 0,
        }
    }

    /// Records a poll that left the dashboard at `revision` with `blocked` blocked calls and
    /// ended with `error`.
    pub fn after_poll(&mut self, revision: u64, blocked: u64, error: Option<&str>) -> PollActions {
        let read_worked = error.is_none();
        if read_worked {
            if self.phase == WatchPhase::LoadingHistory {
                // A saved mark above the log's count was saved for a log that has since been
                // replaced. Kept, it would hide this log's next blocked calls.
                self.read_blocked = if self.saved_read <= blocked {
                    self.saved_read
                } else {
                    0
                };
            }
            self.blocked = blocked;
        }
        let unread = self.unread();
        let publish = revision != self.shown_revision
            || error != self.shown_error.as_deref()
            || unread != self.shown_unread;
        self.shown_revision = revision;
        self.shown_error = error.map(str::to_string);
        self.shown_unread = unread;
        let may_alert = read_worked && self.phase == WatchPhase::Live;
        if read_worked {
            self.phase = WatchPhase::Live;
        }
        PollActions { publish, may_alert }
    }

    /// Marks read the first `seen_blocked` blocked calls, the count the person's screen showed.
    /// The mark only moves forward, and only within the log's count, so a blocked call that
    /// arrived after that screen stays unread.
    pub fn mark_read(&mut self, seen_blocked: u64) -> MarkActions {
        if seen_blocked <= self.read_blocked || seen_blocked > self.blocked {
            return MarkActions {
                publish: false,
                save: None,
            };
        }
        self.read_blocked = seen_blocked;
        self.shown_unread = self.unread();
        MarkActions {
            publish: true,
            save: Some(seen_blocked),
        }
    }

    /// The blocked calls not marked read.
    pub fn unread(&self) -> u64 {
        self.blocked.saturating_sub(self.read_blocked)
    }

    /// The error on screen, for a snapshot published between two polls.
    pub fn shown_error(&self) -> Option<&str> {
        self.shown_error.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_graph::{SpecGraph, Step, tla_bool};

    /// `MaxBlocked` in `specs/DashboardWatch.cfg`.
    const MAX_BLOCKED: u64 = 2;

    /// The watch, the dashboard's revision, and what the last step said. The watch is `None`
    /// in the spec's `Starting` phase, before the saved mark loads.
    #[derive(Clone)]
    struct Walked {
        watch: Option<Watch>,
        revision: u64,
        publish: bool,
        may_alert: bool,
        save: Option<u64>,
    }

    fn number(step: &Step<'_>, name: &str) -> u64 {
        step.to[name].parse().expect("a number in the spec state")
    }

    fn apply(walked: &mut Walked, step: &Step<'_>) {
        if step.action == "Open" {
            walked.watch = Some(Watch::new(number(step, "savedCount")));
            return;
        }
        let watch = walked.watch.as_mut().expect("Open comes first");
        let polled = match step.action {
            "PollFails" => Some(Some(step.to["error"].as_str())),
            "PollQuiet" => Some(None),
            "PollNewLines" => {
                walked.revision += 1;
                Some(None)
            }
            "MarkRead" | "MarkReadIgnored" => None,
            other => panic!("unknown action {other}"),
        };
        if let Some(error) = polled {
            let actions = watch.after_poll(walked.revision, number(step, "blocked"), error);
            walked.publish = actions.publish;
            walked.may_alert = actions.may_alert;
            walked.save = None;
            return;
        }
        let actions = if step.action == "MarkRead" {
            watch.mark_read(number(step, "readBlocked"))
        } else {
            // Every count that moves nothing is ignored the same way.
            let ignored = MarkActions {
                publish: false,
                save: None,
            };
            for seen in 0..=MAX_BLOCKED + 1 {
                if seen <= watch.read_blocked || seen > watch.blocked {
                    assert_eq!(watch.mark_read(seen), ignored, "a mark at {seen}");
                }
            }
            ignored
        };
        walked.publish = actions.publish;
        walked.may_alert = false;
        walked.save = actions.save;
    }

    fn project(walked: &Walked) -> Vec<(&'static str, String)> {
        let mut vars = match &walked.watch {
            None => vec![
                ("phase", "Starting".to_string()),
                ("shownError", "None".to_string()),
                ("shownRevision", "0".to_string()),
                ("shownUnread", "0".to_string()),
                ("savedCount", "0".to_string()),
                ("blocked", "0".to_string()),
                ("readBlocked", "0".to_string()),
            ],
            Some(watch) => vec![
                ("phase", format!("{:?}", watch.phase)),
                (
                    "shownError",
                    watch.shown_error.as_deref().unwrap_or("None").to_string(),
                ),
                ("shownRevision", watch.shown_revision.to_string()),
                ("shownUnread", watch.shown_unread.to_string()),
                ("savedCount", watch.saved_read.to_string()),
                ("blocked", watch.blocked.to_string()),
                ("readBlocked", watch.read_blocked.to_string()),
            ],
        };
        vars.push(("published", tla_bool(walked.publish)));
        vars.push(("mayAlert", tla_bool(walked.may_alert)));
        vars.push(("saveRequested", tla_bool(walked.save.is_some())));
        vars
    }

    #[test]
    fn watch_matches_every_edge_of_the_spec() {
        let graph = SpecGraph::parse(include_str!("../../specs/graphs/DashboardWatch.graph"));
        let walked = graph.walk(
            Walked {
                watch: None,
                revision: 0,
                publish: false,
                may_alert: false,
                save: None,
            },
            |walked| {
                if let (Some(watch), Some(saved)) = (&walked.watch, walked.save) {
                    assert_eq!(saved, watch.read_blocked, "the save holds the new mark");
                }
                project(walked)
            },
            apply,
        );
        assert!(walked > 0);
    }

    #[test]
    fn an_error_from_the_launch_read_clears_when_the_file_recovers() {
        let mut watch = Watch::new(0);
        watch.after_poll(0, 0, Some("permission denied"));
        let recovered = watch.after_poll(0, 0, None);
        assert!(recovered.publish, "the banner must go away");
    }

    #[test]
    fn a_malformed_line_alone_reaches_the_screen() {
        let mut watch = Watch::new(0);
        watch.after_poll(0, 0, None);
        assert!(watch.after_poll(1, 0, None).publish);
    }

    #[test]
    fn history_after_a_failed_launch_read_stays_silent() {
        let mut watch = Watch::new(0);
        watch.after_poll(0, 0, Some("permission denied"));
        assert!(!watch.after_poll(5, 0, None).may_alert);
        assert!(watch.after_poll(6, 0, None).may_alert);
    }

    #[test]
    fn history_beyond_the_saved_mark_is_unread() {
        let mut watch = Watch::new(3);
        watch.after_poll(9, 5, None);
        assert_eq!(
            watch.unread(),
            2,
            "the calls blocked while the app was closed"
        );
    }

    #[test]
    fn a_failed_launch_read_keeps_the_saved_mark() {
        let mut watch = Watch::new(3);
        watch.after_poll(0, 0, Some("permission denied"));
        watch.after_poll(9, 5, None);
        assert_eq!(watch.unread(), 2);
    }

    #[test]
    fn a_saved_mark_above_the_logs_count_leaves_every_call_unread() {
        let mut watch = Watch::new(7);
        watch.after_poll(4, 2, None);
        assert_eq!(watch.unread(), 2, "the mark was saved for a replaced log");
        watch.after_poll(5, 3, None);
        assert_eq!(watch.unread(), 3, "the next blocked call is not hidden");
    }

    #[test]
    fn a_mark_reads_only_the_calls_the_screen_showed() {
        let mut watch = Watch::new(0);
        watch.after_poll(0, 0, None);
        watch.after_poll(3, 3, None);
        let marked = watch.mark_read(2);
        assert_eq!(
            marked,
            MarkActions {
                publish: true,
                save: Some(2)
            }
        );
        assert_eq!(watch.unread(), 1, "the call that arrived after that screen");
        assert_eq!(
            watch.mark_read(2).save,
            None,
            "a repeated mark moves nothing"
        );
        assert_eq!(
            watch.mark_read(4).save,
            None,
            "a count the log never held moves nothing"
        );
    }
}
