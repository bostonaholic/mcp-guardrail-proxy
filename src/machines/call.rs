//! One evaluated call, mirrored from `specs/CallJudgment.tla`.

use crate::control_plane::ApprovalOutcome;
use crate::protocol::Decision;

/// What the policy and the broker settled on, before the audit line is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ruling {
    /// The decision the audit line records.
    pub decision: Decision,
    /// Whether the call goes on to the child once it is audited.
    pub forward: bool,
}

/// Where one call stands. A call ends as `Forwarded` or `Rejected`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallPhase {
    /// The call is waiting for the policy.
    Received,
    /// The policy requires approval, and the broker has not answered.
    AwaitingBroker,
    /// The ruling is settled and takes effect once the audit line is durable.
    Decided(Ruling),
    /// The audit line is durable, and the call goes to the child.
    Forwarded(Decision),
    /// The call gets an error reply, with this decision.
    Rejected(Decision),
}

/// What can happen to a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallEvent {
    /// The policy decided.
    PolicyRuled(Decision),
    /// The broker answered.
    BrokerAnswered(ApprovalOutcome),
    /// The audit sink recorded the event.
    AuditRecorded,
    /// The audit sink failed.
    AuditFailed,
}

const DENIED: Ruling = Ruling {
    decision: Decision::Deny,
    forward: false,
};

impl CallPhase {
    /// The phase after `event`. An event the phase does not expect rejects the call, so a
    /// driver bug fails closed.
    pub fn on(self, event: CallEvent) -> CallPhase {
        match (self, event) {
            (CallPhase::Received, CallEvent::PolicyRuled(Decision::Allow)) => {
                CallPhase::Decided(Ruling {
                    decision: Decision::Allow,
                    forward: true,
                })
            }
            (CallPhase::Received, CallEvent::PolicyRuled(Decision::Deny)) => {
                CallPhase::Decided(DENIED)
            }
            (CallPhase::Received, CallEvent::PolicyRuled(Decision::RequireApproval)) => {
                CallPhase::AwaitingBroker
            }
            (CallPhase::AwaitingBroker, CallEvent::BrokerAnswered(outcome)) => {
                CallPhase::Decided(match outcome {
                    ApprovalOutcome::Approved => Ruling {
                        decision: Decision::RequireApproval,
                        forward: true,
                    },
                    ApprovalOutcome::Denied => DENIED,
                    ApprovalOutcome::Pending => Ruling {
                        decision: Decision::RequireApproval,
                        forward: false,
                    },
                })
            }
            (CallPhase::Decided(ruling), CallEvent::AuditRecorded) if ruling.forward => {
                CallPhase::Forwarded(ruling.decision)
            }
            (CallPhase::Decided(ruling), CallEvent::AuditRecorded) => {
                CallPhase::Rejected(ruling.decision)
            }
            (CallPhase::Decided(ruling), CallEvent::AuditFailed) if ruling.forward => {
                CallPhase::Rejected(Decision::Deny)
            }
            (CallPhase::Decided(ruling), CallEvent::AuditFailed) => {
                CallPhase::Rejected(ruling.decision)
            }
            _ => CallPhase::Rejected(Decision::Deny),
        }
    }

    /// The ruling so far. A phase without one reads as a denial.
    pub fn ruling(self) -> Ruling {
        match self {
            CallPhase::Decided(ruling) => ruling,
            CallPhase::Forwarded(decision) => Ruling {
                decision,
                forward: true,
            },
            CallPhase::Rejected(decision) => Ruling {
                decision,
                forward: false,
            },
            CallPhase::Received | CallPhase::AwaitingBroker => DENIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::spec_graph::{SpecGraph, Step, tla_bool};
    use crate::taint::{SessionTaintState, SourceCategory};

    /// The stages that `Interceptor::judge_call` and its caller run outside `CallPhase`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Stage {
        Idle,
        InMachine,
        Committed,
        Done,
    }

    /// One session's call in progress, with the real taint state.
    #[derive(Clone)]
    struct Walked {
        stage: Stage,
        phase: CallPhase,
        category: Option<SourceCategory>,
        taint: SessionTaintState,
        delivered: bool,
        fallback: bool,
        durable: bool,
    }

    fn source_category(name: &str) -> SourceCategory {
        match name {
            "Benign" => SourceCategory::Benign,
            "Source" => SourceCategory::UntrustedSource,
            "Sink" => SourceCategory::PrivilegedSink,
            other => panic!("unknown category {other}"),
        }
    }

    fn category_name(category: Option<SourceCategory>) -> String {
        match category {
            None => "None".to_string(),
            Some(SourceCategory::Benign) => "Benign".to_string(),
            Some(SourceCategory::UntrustedSource) => "Source".to_string(),
            Some(SourceCategory::PrivilegedSink) => "Sink".to_string(),
        }
    }

    fn decision_name(decision: Option<Decision>) -> String {
        decision.map_or("None".to_string(), |decision| format!("{decision:?}"))
    }

    fn phase_name(walked: &Walked) -> String {
        match (walked.stage, walked.phase) {
            (Stage::Idle, _) => "Idle",
            (Stage::Committed, _) => "Committed",
            (Stage::Done, _) => "Done",
            (Stage::InMachine, CallPhase::Received) => "Received",
            (Stage::InMachine, CallPhase::AwaitingBroker) => "AwaitingBroker",
            (Stage::InMachine, CallPhase::Decided(_)) => "Decided",
            (Stage::InMachine, CallPhase::Forwarded(_)) => "Forwarded",
            (Stage::InMachine, CallPhase::Rejected(_)) => "Rejected",
        }
        .to_string()
    }

    /// The spec's decision and forward variables for the call in flight.
    fn ruling_of(walked: &Walked) -> (Option<Decision>, bool) {
        match (walked.stage, walked.phase) {
            (Stage::Idle, _) | (_, CallPhase::Received) => (None, false),
            (_, CallPhase::AwaitingBroker) => (Some(Decision::RequireApproval), false),
            (_, phase) => (Some(phase.ruling().decision), phase.ruling().forward),
        }
    }

    fn project(walked: &Walked) -> Vec<(&'static str, String)> {
        let (decision, forward) = ruling_of(walked);
        let audit = match (walked.durable, walked.fallback) {
            (true, _) => "Durable",
            (_, true) => "Fallback",
            _ => "None",
        };
        vec![
            ("phase", phase_name(walked)),
            ("category", category_name(walked.category)),
            ("decision", decision_name(decision)),
            ("forward", tla_bool(forward)),
            ("audit", audit.to_string()),
            ("taint", format!("{:?}", walked.taint.level())),
            ("delivered", tla_bool(walked.delivered)),
        ]
    }

    fn apply(walked: &mut Walked, step: &Step<'_>) {
        let event = match step.action {
            "Receive" => {
                walked.stage = Stage::InMachine;
                walked.phase = CallPhase::Received;
                walked.category = Some(source_category(&step.to["category"]));
                return;
            }
            "PolicyAllow" => CallEvent::PolicyRuled(Decision::Allow),
            "PolicyDeny" => CallEvent::PolicyRuled(Decision::Deny),
            "PolicyRequireApproval" => CallEvent::PolicyRuled(Decision::RequireApproval),
            "BrokerApproved" => CallEvent::BrokerAnswered(ApprovalOutcome::Approved),
            "BrokerDenied" => CallEvent::BrokerAnswered(ApprovalOutcome::Denied),
            "BrokerPending" => CallEvent::BrokerAnswered(ApprovalOutcome::Pending),
            "AuditRecorded" => {
                walked.durable = true;
                CallEvent::AuditRecorded
            }
            "AuditFailed" => {
                walked.fallback = true;
                CallEvent::AuditFailed
            }
            "RecordTaint" => {
                let category = walked.category.expect("a call is in flight");
                walked.taint.record_forwarded(1, "tool", category, None);
                walked.stage = Stage::Committed;
                return;
            }
            "Deliver" => {
                walked.delivered = true;
                walked.stage = Stage::Done;
                return;
            }
            "Reply" => {
                walked.stage = Stage::Done;
                return;
            }
            "Complete" => {
                walked.stage = Stage::Idle;
                walked.category = None;
                walked.delivered = false;
                walked.durable = false;
                walked.fallback = false;
                return;
            }
            other => panic!("unknown action {other}"),
        };
        walked.phase = walked.phase.on(event);
    }

    #[test]
    fn call_phase_matches_every_edge_of_the_spec() {
        let walked = SpecGraph::parse(include_str!("../../specs/graphs/CallJudgment.graph")).walk(
            Walked {
                stage: Stage::Idle,
                phase: CallPhase::Received,
                category: None,
                taint: SessionTaintState::new(),
                delivered: false,
                fallback: false,
                durable: false,
            },
            project,
            apply,
        );
        assert!(walked > 0);
    }

    #[test]
    fn an_event_out_of_order_rejects_the_call() {
        let ruling = Ruling {
            decision: Decision::Allow,
            forward: true,
        };
        let early_audit = CallPhase::Received.on(CallEvent::AuditRecorded);
        let second_ruling = CallPhase::Decided(ruling).on(CallEvent::PolicyRuled(Decision::Allow));
        let answer_without_question =
            CallPhase::Received.on(CallEvent::BrokerAnswered(ApprovalOutcome::Approved));
        let after_the_end = CallPhase::Forwarded(Decision::Allow).on(CallEvent::AuditRecorded);
        for phase in [
            early_audit,
            second_ruling,
            answer_without_question,
            after_the_end,
        ] {
            assert_eq!(phase, CallPhase::Rejected(Decision::Deny));
        }
    }
}
