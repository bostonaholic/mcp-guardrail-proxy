//! Turns audit lines into the dashboard state. Pure: no I/O, no UI.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

const AUDIT_EVENT_KIND: &str = "mcp_guardrail_audit";
const MAX_RECENT_EVENTS: usize = 500;

/// The audit fields the app shows. `arguments` is left out on purpose: the app has no need for
/// it, and redaction is pattern-based, so a secret could survive into it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub session_id: String,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub tool_name: String,
    pub decision: String,
    pub rule_id: String,
    pub severity: String,
    pub reason: String,
    pub taint_level: String,
    pub taint_chain: Vec<String>,
    pub forwarded: bool,
}

/// What one line of the log turned out to be.
#[derive(Debug, PartialEq)]
pub enum ParsedLine {
    Event(Box<AuditEvent>),
    /// Valid JSON or text that is not an audit record, such as relayed child output.
    Ignored,
    /// An audit record the app cannot read, which suggests the format moved.
    Malformed,
}

pub fn parse_line(line: &str) -> ParsedLine {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return ParsedLine::Ignored;
    };
    if value.get("event").and_then(|kind| kind.as_str()) != Some(AUDIT_EVENT_KIND) {
        return ParsedLine::Ignored;
    }
    match serde_json::from_value(value) {
        Ok(event) => ParsedLine::Event(Box::new(event)),
        Err(_) => ParsedLine::Malformed,
    }
}

/// One proxy session as far as the log shows. The log has no "session ended" record, so a
/// session stays listed after its proxy exits; `last_seen_ms` is the only hint.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    /// The level before the session's latest call. A call that taints the session shows up here
    /// only on the next call, because audit lines record the level from before the call.
    pub taint_level: String,
    pub calls: u64,
    pub blocked: u64,
    pub last_seen_ms: u64,
}

/// Everything the window and tray show.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Snapshot {
    pub log_path: String,
    pub source_error: Option<String>,
    pub malformed_lines: u64,
    pub total_calls: u64,
    pub total_blocked: u64,
    /// Newest first.
    pub sessions: Vec<SessionSummary>,
    /// Newest first.
    pub events: Vec<AuditEvent>,
}

#[derive(Debug, Default)]
pub struct Dashboard {
    recent: VecDeque<AuditEvent>,
    sessions: BTreeMap<String, SessionSummary>,
    malformed_lines: u64,
    total_calls: u64,
    total_blocked: u64,
}

impl Dashboard {
    /// Folds `lines` into the state and returns the audit events they held.
    pub fn apply_lines(&mut self, lines: &[String]) -> Vec<AuditEvent> {
        let mut events = Vec::new();
        for line in lines {
            match parse_line(line) {
                ParsedLine::Event(event) => {
                    self.apply_event(&event);
                    events.push(*event);
                }
                ParsedLine::Ignored => {}
                ParsedLine::Malformed => self.malformed_lines += 1,
            }
        }
        events
    }

    fn apply_event(&mut self, event: &AuditEvent) {
        let blocked = u64::from(!event.forwarded);
        self.total_calls += 1;
        self.total_blocked += blocked;
        let session = self
            .sessions
            .entry(event.session_id.clone())
            .or_insert_with(|| SessionSummary {
                session_id: event.session_id.clone(),
                taint_level: event.taint_level.clone(),
                calls: 0,
                blocked: 0,
                last_seen_ms: event.timestamp_ms,
            });
        session.taint_level.clone_from(&event.taint_level);
        session.calls += 1;
        session.blocked += blocked;
        session.last_seen_ms = event.timestamp_ms;
        self.recent.push_back(event.clone());
        if self.recent.len() > MAX_RECENT_EVENTS {
            self.recent.pop_front();
        }
    }

    pub fn snapshot(&self, log_path: &str, source_error: Option<String>) -> Snapshot {
        let mut sessions: Vec<SessionSummary> = self.sessions.values().cloned().collect();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.last_seen_ms));
        Snapshot {
            log_path: log_path.to_string(),
            source_error,
            malformed_lines: self.malformed_lines,
            total_calls: self.total_calls,
            total_blocked: self.total_blocked,
            sessions,
            events: self.recent.iter().rev().cloned().collect(),
        }
    }
}

/// The one-line status for the tray menu.
pub fn tray_status(snapshot: &Snapshot) -> String {
    if let Some(error) = &snapshot.source_error {
        return format!("Cannot read audit log: {error}");
    }
    let tainted = snapshot
        .sessions
        .iter()
        .filter(|session| session.taint_level == "Tainted")
        .count();
    format!(
        "{} sessions, {tainted} tainted, {} blocked",
        snapshot.sessions.len(),
        snapshot.total_blocked
    )
}

/// A desktop notification.
#[derive(Debug, PartialEq)]
pub struct Alert {
    pub title: String,
    pub body: String,
}

/// One alert for a batch of new events, so a burst of denials is one notification, not many.
pub fn alert_for(events: &[AuditEvent]) -> Option<Alert> {
    let blocked: Vec<&AuditEvent> = events.iter().filter(|event| !event.forwarded).collect();
    match blocked.as_slice() {
        [] => None,
        [event] => {
            let verb = if event.decision == "require-approval" {
                "Needs approval"
            } else {
                "Blocked"
            };
            Some(Alert {
                title: format!("{verb}: {}", event.tool_name),
                body: event.reason.clone(),
            })
        }
        [.., latest] => Some(Alert {
            title: format!("{} calls blocked", blocked.len()),
            body: format!("Latest: {}", latest.tool_name),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line in the shape the proxy writes, including fields the app ignores.
    fn line(session: &str, sequence: u64, decision: &str, forwarded: bool, taint: &str) -> String {
        serde_json::json!({
            "arguments": {"path": "/etc/shadow"},
            "decision": decision,
            "event": "mcp_guardrail_audit",
            "forwarded": forwarded,
            "latency_us": 262,
            "method": "tools/call",
            "reason": "the reason",
            "rule_id": "the-rule",
            "sequence": sequence,
            "session_id": session,
            "severity": "critical",
            "taint_chain": [],
            "taint_level": taint,
            "timestamp_ms": 1000 + sequence,
            "tool_name": format!("tool-{sequence}"),
        })
        .to_string()
    }

    fn events(lines: &[String]) -> Vec<AuditEvent> {
        Dashboard::default().apply_lines(lines)
    }

    #[test]
    fn parses_the_line_recorded_in_the_readme() {
        let readme_line = r#"{"arguments":{"path":"/etc/shadow","token":"[REDACTED:github-token]"},"decision":"deny","event":"mcp_guardrail_audit","forwarded":false,"latency_us":262,"method":"tools/call","reason":"Reading system credential files is never allowed","rule_id":"deny-system-credential-files","sequence":1,"session_id":"demo-session","severity":"critical","taint_chain":[],"taint_level":"Clean","timestamp_ms":1793105588461,"tool_name":"read_file"}"#;
        let ParsedLine::Event(event) = parse_line(readme_line) else {
            panic!("the README line must parse");
        };
        assert_eq!(event.rule_id, "deny-system-credential-files");
        assert!(!event.forwarded);
    }

    #[test]
    fn ignores_child_output_but_flags_a_broken_audit_record() {
        assert_eq!(parse_line("plain child stderr"), ParsedLine::Ignored);
        assert_eq!(parse_line(r#"{"event":"other"}"#), ParsedLine::Ignored);
        assert_eq!(
            parse_line(r#"{"event":"mcp_guardrail_audit"}"#),
            ParsedLine::Malformed
        );
    }

    #[test]
    fn tracks_each_session_and_lists_the_newest_first() {
        let mut dashboard = Dashboard::default();
        dashboard.apply_lines(&[
            line("a", 1, "allow", true, "Clean"),
            line("a", 2, "deny", false, "Tainted"),
            line("b", 3, "allow", true, "Clean"),
        ]);
        let snapshot = dashboard.snapshot("log", None);
        assert_eq!(snapshot.total_calls, 3);
        assert_eq!(snapshot.total_blocked, 1);
        assert_eq!(snapshot.sessions[0].session_id, "b");
        assert_eq!(snapshot.sessions[1].taint_level, "Tainted");
        assert_eq!(snapshot.sessions[1].blocked, 1);
        assert_eq!(snapshot.events[0].sequence, 3);
        assert_eq!(tray_status(&snapshot), "2 sessions, 1 tainted, 1 blocked");
    }

    #[test]
    fn keeps_only_the_recent_events_but_counts_them_all() {
        let lines: Vec<String> = (0..MAX_RECENT_EVENTS as u64 + 5)
            .map(|sequence| line("a", sequence, "allow", true, "Clean"))
            .collect();
        let mut dashboard = Dashboard::default();
        dashboard.apply_lines(&lines);
        let snapshot = dashboard.snapshot("log", None);
        assert_eq!(snapshot.events.len(), MAX_RECENT_EVENTS);
        assert_eq!(snapshot.total_calls, MAX_RECENT_EVENTS as u64 + 5);
    }

    #[test]
    fn a_source_error_replaces_the_tray_status() {
        let snapshot = Dashboard::default().snapshot("log", Some("denied".to_string()));
        assert_eq!(tray_status(&snapshot), "Cannot read audit log: denied");
    }

    #[test]
    fn allowed_calls_raise_no_alert() {
        assert_eq!(
            alert_for(&events(&[line("a", 1, "allow", true, "Clean")])),
            None
        );
    }

    #[test]
    fn alert_names_a_single_blocked_call() {
        let denied = alert_for(&events(&[line("a", 1, "deny", false, "Clean")]));
        assert_eq!(
            denied,
            Some(Alert {
                title: "Blocked: tool-1".to_string(),
                body: "the reason".to_string()
            })
        );
        let pending = alert_for(&events(&[line(
            "a",
            2,
            "require-approval",
            false,
            "Tainted",
        )]));
        assert_eq!(pending.expect("an alert").title, "Needs approval: tool-2");
    }

    #[test]
    fn a_burst_becomes_one_alert() {
        let alert = alert_for(&events(&[
            line("a", 1, "deny", false, "Clean"),
            line("a", 2, "allow", true, "Clean"),
            line("a", 3, "deny", false, "Clean"),
        ]));
        assert_eq!(
            alert,
            Some(Alert {
                title: "2 calls blocked".to_string(),
                body: "Latest: tool-3".to_string()
            })
        );
    }
}
