//! One watched audit log. It joins `Tail`, `Dashboard`, and `Watch`, so a switch to another log
//! starts all three over, exactly as launch does. It also loads and saves the read mark.

use std::path::{Path, PathBuf};

use crate::audit::{Alert, AuditEvent, Dashboard, Snapshot, alert_for};
use crate::read_mark::{self, ReadMark};
use crate::settings::EffectiveSettings;
use crate::tail::Tail;
use crate::watch::Watch;

/// What one poll found: a snapshot to publish and an alert to send, each when needed.
pub struct Poll {
    pub snapshot: Option<Snapshot>,
    pub alert: Option<Alert>,
}

/// What a mark-read request changed: a snapshot to publish, and why the mark could not be
/// saved, if it could not. An unsaved mark still holds until the app quits.
pub struct Marked {
    pub snapshot: Snapshot,
    pub save_error: Option<String>,
}

pub struct Monitor {
    path: PathBuf,
    log_path: String,
    tail: Tail,
    dashboard: Dashboard,
    watch: Watch,
    notifications: bool,
    mark_file: PathBuf,
}

impl Monitor {
    /// Opens the log and loads the lines already in it as history. The caller must always
    /// publish the snapshot, so the screen names this log even when the read fails.
    /// `mark_file` holds the read mark. Blocked calls in the history that the mark saved for
    /// this log does not name are unread.
    pub fn open(settings: &EffectiveSettings, mark_file: &Path) -> (Self, Snapshot) {
        let path = settings.audit_log_path.clone();
        let log_path = path.display().to_string();
        let mut tail = Tail::new(path.clone());
        let mut dashboard = Dashboard::default();
        let mut watch = Watch::new(read_mark::load(mark_file, &log_path));
        // Lines already in the log are history: the first read that works loads them, and
        // `watch` keeps them from raising a notification.
        let (_, source_error) = read_into(&mut tail, &mut dashboard);
        watch.after_poll(
            dashboard.revision(),
            dashboard.total_blocked(),
            source_error.as_deref(),
        );
        let monitor = Self {
            path,
            log_path,
            tail,
            dashboard,
            watch,
            notifications: settings.notifications,
            mark_file: mark_file.to_path_buf(),
        };
        let first = monitor.snapshot(source_error);
        (monitor, first)
    }

    fn snapshot(&self, source_error: Option<String>) -> Snapshot {
        let read = self.watch.read();
        self.dashboard
            .snapshot(&self.log_path, source_error, self.watch.unread(), |call| {
                read.contains(call)
            })
    }

    /// `Some` only when `settings` names another log: that log's first snapshot, which the
    /// caller publishes. The watched path keeps the dashboard and its counters, and takes only
    /// the new notifications switch.
    pub fn apply(&mut self, settings: &EffectiveSettings) -> Option<Snapshot> {
        if settings.audit_log_path == self.path {
            self.notifications = settings.notifications;
            return None;
        }
        let (next, first) = Self::open(settings, &self.mark_file);
        *self = next;
        Some(first)
    }

    /// Marks read the blocked calls `seen` names in `log_path`, the log and calls the person's
    /// screen showed, and saves the mark. `None` when nothing changed: the screen showed
    /// another log, or no call it named was unread.
    pub fn mark_read(&mut self, log_path: &str, seen: &ReadMark) -> Option<Marked> {
        if log_path != self.log_path {
            return None;
        }
        let actions = self.watch.mark_read(seen);
        let save_error = actions.save.and_then(|mark| {
            read_mark::save(&self.mark_file, &self.log_path, &mark)
                .err()
                .map(|error| error.to_string())
        });
        actions.publish.then(|| Marked {
            snapshot: self.snapshot(self.watch.shown_error().map(str::to_string)),
            save_error,
        })
    }

    /// With notifications off, a poll still publishes, and the alerts it drops never replay.
    pub fn poll(&mut self) -> Poll {
        let (events, error) = read_into(&mut self.tail, &mut self.dashboard);
        let actions = self.watch.after_poll(
            self.dashboard.revision(),
            self.dashboard.total_blocked(),
            error.as_deref(),
        );
        let snapshot = actions.publish.then(|| self.snapshot(error));
        let alert = if actions.may_alert && self.notifications {
            alert_for(&events)
        } else {
            None
        };
        Poll { snapshot, alert }
    }
}

/// Reads the log into the dashboard. Returns the new audit events and any read error.
fn read_into(tail: &mut Tail, dashboard: &mut Dashboard) -> (Vec<AuditEvent>, Option<String>) {
    match tail.read_new_lines() {
        Ok(lines) => (dashboard.apply_lines(&lines), None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    use super::*;

    fn append(path: &Path, text: &str) {
        let mut file = File::options()
            .append(true)
            .create(true)
            .open(path)
            .expect("open the log");
        file.write_all(text.as_bytes()).expect("append to the log");
    }

    /// One audit line in the shape the proxy writes, with its newline.
    fn line(tool: &str, forwarded: bool) -> String {
        let decision = if forwarded { "allow" } else { "deny" };
        let record = serde_json::json!({
            "decision": decision,
            "event": "mcp_guardrail_audit",
            "forwarded": forwarded,
            "reason": "the reason",
            "rule_id": "the-rule",
            "sequence": 1,
            "session_id": "session",
            "severity": "critical",
            "taint_chain": [],
            "taint_level": "Clean",
            "timestamp_ms": 1000,
            "tool_name": tool,
        });
        format!("{record}\n")
    }

    fn settings_for(path: &Path) -> EffectiveSettings {
        EffectiveSettings {
            audit_log_path: path.to_path_buf(),
            notifications: true,
        }
    }

    /// Opens `settings` with a read mark file that does not exist yet, next to nothing else.
    fn open(settings: &EffectiveSettings) -> (tempfile::TempDir, Monitor, Snapshot) {
        let state = tempfile::tempdir().expect("create a temp dir");
        let (monitor, first) = Monitor::open(settings, &state.path().join("read-mark.json"));
        (state, monitor, first)
    }

    fn tool_names(snapshot: &Snapshot) -> Vec<&str> {
        snapshot
            .events
            .iter()
            .map(|call| call.event.tool_name.as_str())
            .collect()
    }

    fn unread_tools(snapshot: &Snapshot) -> Vec<&str> {
        snapshot
            .events
            .iter()
            .filter(|call| call.unread)
            .map(|call| call.event.tool_name.as_str())
            .collect()
    }

    #[test]
    fn a_new_path_loads_its_lines_as_history_without_an_alert() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let old = dir.path().join("old.jsonl");
        append(&old, &line("old-call", true));
        let with_blocked_calls = dir.path().join("blocked.jsonl");
        append(&with_blocked_calls, &line("blocked-first", false));
        append(&with_blocked_calls, &line("blocked-second", false));
        let empty = dir.path().join("empty.jsonl");
        append(&empty, "");
        let missing = dir.path().join("missing.jsonl");
        let plain = dir.path().join("plain");
        append(&plain, "");
        let under_a_file = plain.join("audit.jsonl");
        let rows: [(&str, &Path, &[&str], bool); 4] = [
            (
                "a file that holds blocked calls",
                &with_blocked_calls,
                &["blocked-second", "blocked-first"],
                false,
            ),
            ("a file of 0 bytes", &empty, &[], false),
            ("a missing file", &missing, &[], false),
            ("a path under a regular file", &under_a_file, &[], true),
        ];
        for (label, path, tools, read_fails) in rows {
            let (_state, mut monitor, _) = open(&settings_for(&old));
            monitor.poll();
            let switched = monitor.apply(&settings_for(path));
            assert_eq!(
                switched.as_ref().map(|snapshot| snapshot.log_path.clone()),
                Some(path.display().to_string()),
                "{label}: the switch publishes the new path at once"
            );
            let switched = switched.expect("the switch published a snapshot");
            assert_eq!(
                tool_names(&switched),
                tools,
                "{label}: only the new file's events, newest first"
            );
            assert_eq!(
                switched.source_error.is_some(),
                read_fails,
                "{label}: the read error shows in the snapshot"
            );
            assert_eq!(
                monitor.poll().alert,
                None,
                "{label}: lines already in the new file raise no alert"
            );
        }
    }

    #[test]
    fn after_a_switch_only_the_new_file_feeds_the_dashboard_and_alerts() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let old = dir.path().join("old.jsonl");
        append(&old, &line("old-history", true));
        let new = dir.path().join("new.jsonl");
        append(&new, "");
        let (_state, mut monitor, _) = open(&settings_for(&old));
        monitor.apply(&settings_for(&new));
        append(&new, &line("new-blocked", false));
        append(&old, &line("old-later", true));
        let polled = monitor.poll();
        assert_eq!(
            polled.alert.map(|alert| alert.title),
            Some("Blocked: new-blocked".to_string()),
            "a new blocked call in the new file alerts"
        );
        let snapshot = polled.snapshot.expect("the new line publishes a snapshot");
        assert_eq!(
            tool_names(&snapshot),
            ["new-blocked"],
            "the old file no longer feeds the dashboard"
        );
    }

    #[test]
    fn the_same_path_keeps_the_dashboard() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        append(&log, &line("first", true));
        let (_state, mut monitor, _) = open(&settings_for(&log));
        append(&log, &line("second", true));
        assert!(
            monitor.apply(&settings_for(&log)).is_none(),
            "the watched path publishes nothing"
        );
        assert_eq!(
            monitor.poll().snapshot.map(|snapshot| snapshot.total_calls),
            Some(2),
            "the next poll adds the new line to the kept counters"
        );
    }

    #[test]
    fn notifications_off_still_publish_but_never_alert() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        append(&log, "");
        let off = EffectiveSettings {
            audit_log_path: log.clone(),
            notifications: false,
        };
        let (_state, mut monitor, _) = open(&off);
        append(&log, &line("blocked-while-off", false));
        let while_off = monitor.poll();
        assert_eq!(
            while_off.snapshot.map(|snapshot| snapshot.total_blocked),
            Some(1),
            "the dashboard and tray still update"
        );
        assert_eq!(
            while_off.alert, None,
            "no alert while notifications are off"
        );
        assert!(
            monitor.apply(&settings_for(&log)).is_none(),
            "turning notifications on keeps the dashboard"
        );
        assert_eq!(
            monitor.poll().alert,
            None,
            "an alert dropped while off never replays"
        );
        append(&log, &line("blocked-after-on", false));
        assert_eq!(
            monitor.poll().alert.map(|alert| alert.title),
            Some("Blocked: blocked-after-on".to_string()),
            "the next blocked call alerts"
        );
    }

    #[test]
    fn a_blocked_call_is_unread_until_it_is_marked_read() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        append(&log, &line("history-blocked", false));
        let (_state, mut monitor, first) = open(&settings_for(&log));
        assert_eq!(
            first.unread_blocked, 1,
            "with no saved mark, a blocked call in the history is unread"
        );
        append(&log, &line("allowed", true));
        append(&log, &line("live-blocked", false));
        let polled = monitor.poll().snapshot.expect("new lines publish");
        assert_eq!(polled.unread_blocked, 2, "an allowed call is never unread");
        let marked = monitor
            .mark_read(&polled.log_path, &ReadMark::through(polled.total_blocked))
            .expect("the mark publishes");
        assert_eq!(marked.snapshot.unread_blocked, 0);
        assert_eq!(unread_tools(&polled), ["live-blocked", "history-blocked"]);
        assert_eq!(unread_tools(&marked.snapshot), [""; 0]);
        assert_eq!(marked.snapshot.total_blocked, 2, "the total stays");
        assert_eq!(marked.save_error, None);
        append(&log, &line("blocked-after-the-mark", false));
        assert_eq!(
            monitor
                .poll()
                .snapshot
                .map(|snapshot| snapshot.unread_blocked),
            Some(1)
        );
    }

    #[test]
    fn a_mark_covers_only_the_log_and_count_the_screen_showed() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        append(&log, &line("first", false));
        let (_state, mut monitor, shown) = open(&settings_for(&log));
        append(&log, &line("arrived-after-that-screen", false));
        monitor.poll();
        assert!(
            monitor
                .mark_read("/another/log.jsonl", &ReadMark::through(2))
                .is_none(),
            "a screen that showed another log marks nothing"
        );
        let marked = monitor
            .mark_read(&shown.log_path, &ReadMark::through(shown.total_blocked))
            .expect("the mark publishes");
        assert_eq!(
            marked.snapshot.unread_blocked, 1,
            "the call the screen had not shown stays unread"
        );
        assert!(
            monitor
                .mark_read(&shown.log_path, &ReadMark::through(shown.total_blocked))
                .is_none(),
            "the same mark again changes nothing"
        );
    }

    #[test]
    fn the_mark_survives_a_relaunch_and_calls_blocked_meanwhile_are_unread() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        let mark_file = dir.path().join("config").join("read-mark.json");
        append(&log, &line("read-before-quit", false));
        let (mut monitor, first) = Monitor::open(&settings_for(&log), &mark_file);
        monitor
            .mark_read(&first.log_path, &ReadMark::through(first.total_blocked))
            .expect("the mark publishes");
        drop(monitor);
        let (_, relaunched) = Monitor::open(&settings_for(&log), &mark_file);
        assert_eq!(relaunched.unread_blocked, 0, "the mark was saved");
        append(&log, &line("blocked-while-closed", false));
        let (mut monitor, relaunched) = Monitor::open(&settings_for(&log), &mark_file);
        assert_eq!(relaunched.unread_blocked, 1);
        assert_eq!(
            monitor.poll().alert,
            None,
            "an unread call from the history still raises no notification"
        );
    }

    #[test]
    fn a_selected_call_is_read_and_stays_read_after_a_relaunch() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        let mark_file = dir.path().join("config").join("read-mark.json");
        append(&log, &line("first", false));
        append(&log, &line("second", false));
        append(&log, &line("third", false));
        let (mut monitor, first) = Monitor::open(&settings_for(&log), &mark_file);
        assert_eq!(unread_tools(&first), ["third", "second", "first"]);
        let second = first.events[1]
            .blocked_number
            .expect("a blocked call has a number");
        let marked = monitor
            .mark_read(&first.log_path, &ReadMark::of([second]))
            .expect("the mark publishes");
        assert_eq!(unread_tools(&marked.snapshot), ["third", "first"]);
        assert_eq!(marked.snapshot.unread_blocked, 2);
        drop(monitor);
        let (_, relaunched) = Monitor::open(&settings_for(&log), &mark_file);
        assert_eq!(unread_tools(&relaunched), ["third", "first"]);
    }

    #[test]
    fn a_mark_saved_for_a_longer_log_leaves_a_replaced_log_unread() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        let mark_file = dir.path().join("read-mark.json");
        append(&log, &line("old-first", false));
        append(&log, &line("old-second", false));
        let (mut monitor, first) = Monitor::open(&settings_for(&log), &mark_file);
        monitor
            .mark_read(&first.log_path, &ReadMark::through(first.total_blocked))
            .expect("the mark publishes");
        drop(monitor);
        std::fs::write(&log, line("new-first", false)).expect("replace the log");
        let (_, relaunched) = Monitor::open(&settings_for(&log), &mark_file);
        assert_eq!(
            relaunched.unread_blocked, 1,
            "a mark of 2 cannot describe a log with 1 blocked call"
        );
    }

    #[test]
    fn a_mark_keeps_the_read_error_on_screen() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        append(&log, &line("blocked", false));
        let (_state, mut monitor, first) = open(&settings_for(&log));
        std::fs::remove_file(&log).expect("remove the log");
        std::fs::create_dir(&log).expect("put a folder where the log was");
        let failed = monitor.poll().snapshot.expect("the error publishes");
        assert!(failed.source_error.is_some());
        let marked = monitor
            .mark_read(&first.log_path, &ReadMark::through(first.total_blocked))
            .expect("the mark publishes");
        assert_eq!(marked.snapshot.unread_blocked, 0);
        assert_eq!(
            marked.snapshot.source_error, failed.source_error,
            "the snapshot a mark publishes still shows the read error"
        );
    }

    #[test]
    fn a_mark_that_cannot_be_saved_still_holds_and_reports_why() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let log = dir.path().join("audit.jsonl");
        append(&log, &line("blocked", false));
        let plain = dir.path().join("plain");
        append(&plain, "");
        let mark_file = plain.join("read-mark.json");
        let (mut monitor, first) = Monitor::open(&settings_for(&log), &mark_file);
        let marked = monitor
            .mark_read(&first.log_path, &ReadMark::through(first.total_blocked))
            .expect("the mark publishes");
        assert_eq!(
            marked.snapshot.unread_blocked, 0,
            "the mark holds for this run"
        );
        assert!(marked.save_error.is_some(), "the failed save is reported");
    }

    #[test]
    fn another_log_starts_with_its_own_blocked_calls_unread() {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let old = dir.path().join("old.jsonl");
        append(&old, &line("old-blocked", false));
        let new = dir.path().join("new.jsonl");
        append(&new, &line("new-blocked-first", false));
        append(&new, &line("new-blocked-second", false));
        let (_state, mut monitor, first) = open(&settings_for(&old));
        monitor
            .mark_read(&first.log_path, &ReadMark::through(first.total_blocked))
            .expect("the mark publishes");
        let switched = monitor
            .apply(&settings_for(&new))
            .expect("the switch publishes");
        assert_eq!(
            switched.unread_blocked, 2,
            "the old log's mark says nothing about the new log"
        );
    }
}
