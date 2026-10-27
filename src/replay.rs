//! Replays a corpus of host frames through the real interceptor and scores each outcome.

use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::control_plane::PendingApprovalBroker;
use crate::policy::PolicyEngine;
use crate::protocol::Decision;
use crate::proxy::{Interceptor, Verdict};
use crate::telemetry::{JsonlAuditSink, SecurityAuditEvent, SharedLineWriter};

/// The slowest evaluation the replay accepts, in microseconds.
const LATENCY_BUDGET_US: u64 = 1000;

/// A set of scenarios, each replayed against one fresh session.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCorpus {
    /// The scenarios, replayed in order.
    pub scenarios: Vec<Scenario>,
}

/// One session: frames sent in order, sharing one taint state.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// The scenario's unique name, used in failure lines.
    pub id: String,
    /// What the scenario shows.
    pub description: String,
    /// The frames of the session, in order.
    pub steps: Vec<Step>,
}

/// One host frame and the outcome it must produce.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The raw host line, without its newline; may be malformed on purpose.
    pub frame: String,
    /// The outcome the interceptor must produce.
    pub expect: Expectation,
}

/// The outcome a step must produce.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// The decision the one new audit line must hold; `None` means the step writes no audit line.
    #[serde(default)]
    pub decision: Option<Decision>,
    /// Whether the frame reaches the child.
    pub forwarded: bool,
    /// The error code of the reply to the host; `None` means the step forwards.
    #[serde(default)]
    pub error_code: Option<i64>,
    /// Marks a tainted exfiltration attempt, which must never be forwarded.
    #[serde(default)]
    pub exfiltration: bool,
    /// Strings that must not appear in the step's audit bytes.
    #[serde(default)]
    pub audit_must_not_contain: Vec<String>,
    /// The id of the rule the audit line must name.
    #[serde(default)]
    pub rule_id: Option<String>,
}

/// How a replay went: step matches, blocking accuracy, and evaluation latency.
#[derive(Debug)]
pub struct ReplayReport {
    /// Scenarios in the corpus.
    pub scenarios_total: usize,
    /// Scenarios in which every step matched.
    pub scenarios_matched: usize,
    /// Steps in the corpus.
    pub steps_total: usize,
    /// Steps with no mismatch.
    pub steps_matched: usize,
    /// Steps that wrote an audit line.
    pub evaluated_steps: usize,
    /// Steps marked as exfiltration attempts.
    pub exfiltration_steps: usize,
    /// Calls expected to be denied or held that were not forwarded.
    pub true_positives: usize,
    /// Calls expected to be forwarded that were not.
    pub false_positives: usize,
    /// Calls expected to be denied or held that were forwarded.
    pub false_negatives: usize,
    /// Exfiltration attempts that were forwarded.
    pub exfiltration_false_negatives: usize,
    /// The slowest evaluation among the audit lines, in microseconds.
    pub max_latency_us: u64,
    /// The mean evaluation time among the audit lines, 0.0 when no step was evaluated.
    pub mean_latency_us: f64,
    /// One `FAIL` line per mismatch.
    pub failures: Vec<String>,
}

impl ReplayCorpus {
    /// Reads and checks a corpus file; the error says what is wrong.
    pub fn from_path(path: &Path) -> Result<ReplayCorpus, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read corpus {}: {error}", path.display()))?;
        let corpus: ReplayCorpus = serde_json::from_str(&text)
            .map_err(|error| format!("invalid corpus {}: {error}", path.display()))?;
        for scenario in &corpus.scenarios {
            for (index, step) in scenario.steps.iter().enumerate() {
                if step.expect.exfiltration && step.expect.forwarded {
                    return Err(format!(
                        "invalid corpus {}: scenario {} step {}: an exfiltration step cannot expect forwarded=true",
                        path.display(),
                        scenario.id,
                        index + 1
                    ));
                }
            }
        }
        Ok(corpus)
    }
}

/// An in-memory audit destination that the replay reads back after each step.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    /// Takes the bytes written since the previous call.
    fn take(&self) -> Vec<u8> {
        let mut bytes = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *bytes)
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Replays every scenario through a fresh [`Interceptor`] and scores each step.
pub fn run_replay(engine: &PolicyEngine, corpus: &ReplayCorpus) -> ReplayReport {
    let mut report = ReplayReport {
        scenarios_total: corpus.scenarios.len(),
        scenarios_matched: 0,
        steps_total: 0,
        steps_matched: 0,
        evaluated_steps: 0,
        exfiltration_steps: 0,
        true_positives: 0,
        false_positives: 0,
        false_negatives: 0,
        exfiltration_false_negatives: 0,
        max_latency_us: 0,
        mean_latency_us: 0.0,
        failures: Vec::new(),
    };
    let mut latency_sum_us: u64 = 0;
    let mut latency_count: u64 = 0;
    for scenario in &corpus.scenarios {
        let audit = SharedBuffer::default();
        let mut interceptor = Interceptor::new(
            scenario.id.clone(),
            engine.clone(),
            Box::new(JsonlAuditSink::from_writer(Box::new(audit.clone()))),
            Box::new(PendingApprovalBroker),
            SharedLineWriter::stderr(),
        );
        let mut scenario_matched = true;
        for (index, step) in scenario.steps.iter().enumerate() {
            let verdict = interceptor.handle_host_line(&step.frame);
            let forwarded = matches!(verdict, Verdict::Forward(_));
            let audit_bytes = audit.take();
            let audit_text = String::from_utf8_lossy(&audit_bytes);
            let lines: Vec<&str> = audit_text.lines().filter(|line| !line.is_empty()).collect();
            let events: Vec<Result<SecurityAuditEvent, serde_json::Error>> = lines
                .iter()
                .map(|line| serde_json::from_str(line))
                .collect();

            let mismatches = step_mismatches(&step.expect, &verdict, &audit_text, &events);
            let label = format!("FAIL {} step {}", scenario.id, index + 1);
            let matched = mismatches.is_empty();
            report.failures.extend(
                mismatches
                    .into_iter()
                    .map(|line| format!("{label}: {line}")),
            );

            report.steps_total += 1;
            report.steps_matched += usize::from(matched);
            scenario_matched &= matched;
            if !events.is_empty() {
                report.evaluated_steps += 1;
            }
            for event in events.iter().flatten() {
                report.max_latency_us = report.max_latency_us.max(event.latency_us);
                latency_sum_us = latency_sum_us.saturating_add(event.latency_us);
                latency_count += 1;
            }
            let positive = matches!(
                step.expect.decision,
                Some(Decision::Deny | Decision::RequireApproval)
            );
            if positive {
                if forwarded {
                    report.false_negatives += 1;
                } else {
                    report.true_positives += 1;
                }
            }
            if step.expect.forwarded && !forwarded {
                report.false_positives += 1;
            }
            if step.expect.exfiltration {
                report.exfiltration_steps += 1;
                if forwarded {
                    report.exfiltration_false_negatives += 1;
                }
            }
        }
        report.scenarios_matched += usize::from(scenario_matched);
    }
    if latency_count > 0 {
        report.mean_latency_us = latency_sum_us as f64 / latency_count as f64;
    }
    report
}

/// Every way the step's outcome departs from `expect`, as `expected ..., got ...` texts.
fn step_mismatches(
    expect: &Expectation,
    verdict: &Verdict,
    audit_text: &str,
    events: &[Result<SecurityAuditEvent, serde_json::Error>],
) -> Vec<String> {
    let mut mismatches = Vec::new();
    let forwarded = matches!(verdict, Verdict::Forward(_));
    if expect.forwarded != forwarded {
        mismatches.push(format!(
            "expected forwarded={}, got {forwarded}",
            expect.forwarded
        ));
    }
    let reply_code = match verdict {
        Verdict::Reply(response) => response.error.as_ref().map(|error| error.code),
        Verdict::Forward(_) => None,
    };
    match expect.error_code {
        Some(code) if reply_code != Some(code) => mismatches.push(format!(
            "expected error_code={code}, got {}",
            describe_code(forwarded, reply_code)
        )),
        None if !forwarded => mismatches.push(format!(
            "expected error_code=none, got {}",
            describe_code(forwarded, reply_code)
        )),
        _ => {}
    }

    for event in events {
        if let Err(error) = event {
            mismatches.push(format!("expected audit_line=valid JSON, got {error}"));
        }
    }
    let first_event = events.iter().flatten().next();
    match expect.decision {
        Some(decision) => {
            if events.len() != 1 {
                mismatches.push(format!("expected audit_lines=1, got {}", events.len()));
            } else if let Some(event) = first_event
                && event.decision != decision
            {
                mismatches.push(format!(
                    "expected decision={}, got {}",
                    decision_name(decision),
                    decision_name(event.decision)
                ));
            }
        }
        None if !events.is_empty() => {
            mismatches.push(format!("expected audit_lines=0, got {}", events.len()))
        }
        None => {}
    }
    if let Some(rule_id) = &expect.rule_id {
        let got = first_event.map_or("none", |event| event.rule_id.as_str());
        if got != rule_id {
            mismatches.push(format!("expected rule_id={rule_id}, got {got}"));
        }
    }
    for forbidden in &expect.audit_must_not_contain {
        if audit_text.contains(forbidden.as_str()) {
            mismatches.push(format!(
                "expected audit_must_not_contain={forbidden} absent, got present"
            ));
        }
    }
    mismatches
}

/// The reply's error code for a failure line, or what the step did instead.
fn describe_code(forwarded: bool, reply_code: Option<i64>) -> String {
    match (forwarded, reply_code) {
        (_, Some(code)) => code.to_string(),
        (true, None) => "forwarded".to_string(),
        (false, None) => "reply without error".to_string(),
    }
}

/// The decision's name as it appears in the policy file and the audit log.
fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::RequireApproval => "require-approval",
    }
}

impl ReplayReport {
    /// True when every step matched, nothing slipped through, and evaluation stayed in budget.
    pub fn passed(&self) -> bool {
        self.steps_matched == self.steps_total
            && self.false_negatives == 0
            && self.exfiltration_false_negatives == 0
            && self.max_latency_us < LATENCY_BUDGET_US
    }

    /// The report as text: summary lines, one line per failure, then the result.
    pub fn render(&self) -> String {
        let precision = percentage(
            self.true_positives,
            self.true_positives + self.false_positives,
        );
        let recall = percentage(
            self.true_positives,
            self.true_positives + self.false_negatives,
        );
        let latency = if self.evaluated_steps == 0 {
            format!("latency: max n/a, mean n/a (budget {LATENCY_BUDGET_US} us)")
        } else {
            format!(
                "latency: max {} us, mean {:.1} us (budget {LATENCY_BUDGET_US} us)",
                self.max_latency_us, self.mean_latency_us
            )
        };
        let mut lines = vec![
            format!(
                "replay: {}/{} scenarios matched, {}/{} steps matched",
                self.scenarios_matched, self.scenarios_total, self.steps_matched, self.steps_total
            ),
            format!(
                "blocked: tp {}, fp {}, fn {} (precision {precision}, recall {recall})",
                self.true_positives, self.false_positives, self.false_negatives
            ),
            format!(
                "exfiltration: {} steps, {} false negatives",
                self.exfiltration_steps, self.exfiltration_false_negatives
            ),
            latency,
        ];
        lines.extend(self.failures.iter().cloned());
        lines.push(format!(
            "result: {}",
            if self.passed() { "PASS" } else { "FAIL" }
        ));
        lines.join("\n")
    }
}

/// `part` of `whole` as a percentage with one decimal, or `n/a` when `whole` is 0.
fn percentage(part: usize, whole: usize) -> String {
    if whole == 0 {
        "n/a".to_string()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / whole as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::PendingApprovalBroker;
    use crate::policy::PolicyEngine;
    use crate::protocol::{JsonRpcMessage, encode_frame};
    use crate::proxy::{Interceptor, Verdict};
    use crate::telemetry::{JsonlAuditSink, SharedLineWriter};
    use std::path::Path;

    const DEFAULT_POLICY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/policies/default-policy.toml");
    const SHIPPED_CORPUS: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/replay-corpus.json");

    fn default_engine() -> PolicyEngine {
        PolicyEngine::from_path(Path::new(DEFAULT_POLICY)).expect("the default policy loads")
    }

    fn shipped_corpus() -> ReplayCorpus {
        ReplayCorpus::from_path(Path::new(SHIPPED_CORPUS)).expect("the shipped corpus loads")
    }

    #[test]
    fn shipped_corpus_passes_on_default_policy() {
        let report = run_replay(&default_engine(), &shipped_corpus());
        assert_eq!(report.steps_total, 36);
        assert_eq!(
            report.steps_matched, 36,
            "mismatched steps: {:#?}",
            report.failures
        );
        assert_eq!(report.false_negatives, 0);
        assert_eq!(report.exfiltration_false_negatives, 0);
        assert_eq!(report.exfiltration_steps, 7);
        assert_eq!(report.true_positives, 15);
    }

    #[test]
    fn shipped_corpus_has_the_ten_scenario_ids() {
        let corpus = shipped_corpus();
        let ids: Vec<&str> = corpus
            .scenarios
            .iter()
            .map(|scenario| scenario.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "clean-benign-operations",
                "email-injection-shell-exfiltration",
                "web-fetch-slack-webhook-exfiltration",
                "github-issue-ssh-key-read",
                "tainted-read-only-search-allowed",
                "tainted-workspace-edit-requires-approval",
                "clean-direct-shadow-read-blocked",
                "secret-redaction-in-audit",
                "malformed-json-rpc-handling",
                "external-resource-url-query-exfiltration",
            ]
        );
    }

    /// What the host or the child sees for one verdict.
    fn rendered(verdict: Verdict) -> String {
        match verdict {
            Verdict::Forward(frame) => format!("forward {frame}"),
            Verdict::Reply(response) => format!(
                "reply {}",
                encode_frame(&JsonRpcMessage::Response(response))
            ),
        }
    }

    /// Every step's verdict, with one fresh interceptor per scenario.
    fn corpus_verdicts(engine: &PolicyEngine, corpus: &ReplayCorpus) -> Vec<String> {
        let mut verdicts = Vec::new();
        for scenario in &corpus.scenarios {
            let mut interceptor = Interceptor::new(
                scenario.id.clone(),
                engine.clone(),
                Box::new(JsonlAuditSink::from_writer(Box::new(std::io::sink()))),
                Box::new(PendingApprovalBroker),
                SharedLineWriter::from_writer(Box::new(std::io::sink())),
            );
            for (index, step) in scenario.steps.iter().enumerate() {
                let verdict = rendered(interceptor.handle_host_line(&step.frame));
                verdicts.push(format!("{} step {}: {verdict}", scenario.id, index + 1));
            }
        }
        verdicts
    }

    /// The first verdict that differs between two runs, as (first, second).
    fn first_difference(first: &[String], second: &[String]) -> Option<(String, String)> {
        first
            .iter()
            .zip(second)
            .find(|(one, other)| one != other)
            .map(|(one, other)| (one.clone(), other.clone()))
    }

    #[test]
    fn replay_is_deterministic_across_runs() {
        let engine = default_engine();
        let corpus = shipped_corpus();
        let first = corpus_verdicts(&engine, &corpus);
        let second = corpus_verdicts(&engine, &corpus);
        assert_eq!(first.len(), 36);
        assert_eq!(second.len(), 36);
        assert_eq!(first_difference(&first, &second), None);
    }
}
