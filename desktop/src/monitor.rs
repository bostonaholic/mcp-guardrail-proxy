//! One watched audit log. It joins `Tail`, `Dashboard`, and `Watch`, so a switch to another log
//! starts all three over, exactly as launch does.

use std::path::PathBuf;

use crate::audit::{Alert, AuditEvent, Dashboard, Snapshot, alert_for};
use crate::settings::EffectiveSettings;
use crate::tail::Tail;
use crate::watch::Watch;

/// What one poll found: a snapshot to publish and an alert to send, each when needed.
pub struct Poll {
    pub snapshot: Option<Snapshot>,
    pub alert: Option<Alert>,
}

pub struct Monitor {
    path: PathBuf,
    log_path: String,
    tail: Tail,
    dashboard: Dashboard,
    watch: Watch,
    notifications: bool,
}

impl Monitor {
    /// Opens the log and loads the lines already in it as history. The caller must always
    /// publish the snapshot, so the screen names this log even when the read fails.
    pub fn open(settings: &EffectiveSettings) -> (Self, Snapshot) {
        let path = settings.audit_log_path.clone();
        let log_path = path.display().to_string();
        let mut tail = Tail::new(path.clone());
        let mut dashboard = Dashboard::default();
        let mut watch = Watch::new();
        // Lines already in the log are history: the first read that works loads them, and
        // `watch` keeps them from raising a notification.
        let (_, source_error) = read_into(&mut tail, &mut dashboard);
        watch.after_poll(dashboard.revision(), source_error.as_deref());
        let first = dashboard.snapshot(&log_path, source_error);
        let monitor = Self {
            path,
            log_path,
            tail,
            dashboard,
            watch,
            notifications: settings.notifications,
        };
        (monitor, first)
    }

    /// `Some` only when `settings` names another log: that log's first snapshot, which the
    /// caller publishes. The watched path keeps the dashboard and its counters, and takes only
    /// the new notifications switch.
    pub fn apply(&mut self, settings: &EffectiveSettings) -> Option<Snapshot> {
        if settings.audit_log_path == self.path {
            self.notifications = settings.notifications;
            return None;
        }
        let (next, first) = Self::open(settings);
        *self = next;
        Some(first)
    }

    /// With notifications off, a poll still publishes, and the alerts it drops never replay.
    pub fn poll(&mut self) -> Poll {
        let (events, error) = read_into(&mut self.tail, &mut self.dashboard);
        let actions = self
            .watch
            .after_poll(self.dashboard.revision(), error.as_deref());
        let snapshot = actions
            .publish
            .then(|| self.dashboard.snapshot(&self.log_path, error));
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

    fn tool_names(snapshot: &Snapshot) -> Vec<&str> {
        snapshot
            .events
            .iter()
            .map(|event| event.tool_name.as_str())
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
            let (mut monitor, _) = Monitor::open(&settings_for(&old));
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
        let (mut monitor, _) = Monitor::open(&settings_for(&old));
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
        let (mut monitor, _) = Monitor::open(&settings_for(&log));
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
        let (mut monitor, _) = Monitor::open(&off);
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
}
