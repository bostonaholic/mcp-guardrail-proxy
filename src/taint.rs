//! Monotonic session taint state machine, mirrored from `specs/McpGuardrailTaint.tla`.

use serde::{Deserialize, Serialize};

use crate::protocol::Decision;

/// The most events `SessionTaintState` keeps; older events are dropped.
pub const MAX_TAINT_HISTORY: usize = 4096;

/// The most `Tainted` events `taint_chain` lists before it summarizes the rest.
const MAX_CHAIN_ENTRIES: usize = 16;

/// What kind of tool a call reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceCategory {
    /// A tool that neither reads untrusted data nor performs a privileged action.
    Benign,
    /// A tool whose results taint the session once forwarded.
    UntrustedSource,
    /// A tool that must not run in a tainted session without an override.
    PrivilegedSink,
}

/// Whether a call's arguments carry sensitive data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArgSensitivity {
    /// The arguments hold nothing sensitive.
    Safe,
    /// The arguments hold sensitive data, so the call is always denied.
    Sensitive,
}

/// Whether the session has forwarded an untrusted source call since the last reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintLevel {
    /// No untrusted source call has been forwarded since the last reset.
    Clean,
    /// An untrusted source call has been forwarded since the last reset.
    Tainted,
}

/// The forwarded call that tainted the session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintOrigin {
    /// The step counter value of the forwarded call.
    pub sequence: u64,
    /// The name of the tool that was called.
    pub tool_name: String,
    /// The category of the tool that was called.
    pub category: SourceCategory,
    /// Free-form context about why the call tainted the session.
    pub detail: Option<String>,
}

/// One entry in the taint history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintEvent {
    /// A forwarded untrusted source call.
    Tainted(TaintOrigin),
    /// An explicit reset that returned the session to `Clean`.
    Reset {
        /// The step counter value when the reset happened.
        sequence: u64,
    },
}

/// A tool call reduced to the fields that the taint rule reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbstractCall {
    /// The name of the tool being called.
    pub tool_name: String,
    /// The category of the tool being called.
    pub category: SourceCategory,
    /// Whether the arguments carry sensitive data.
    pub sensitivity: ArgSensitivity,
    /// Whether an approval overrides the tainted-sink denial.
    pub override_allowed: bool,
}

/// The audit record of one evaluated call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// The step counter value of the call.
    pub sequence: u64,
    /// The name of the tool that was called.
    pub tool_name: String,
    /// The category of the tool that was called.
    pub category: SourceCategory,
    /// Whether the call's arguments carried sensitive data.
    pub sensitivity: ArgSensitivity,
    /// The session taint level before the call updated it.
    pub taint_at_evaluation: TaintLevel,
    /// What the rule decided.
    pub decision: Decision,
}

/// The result of one `step`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepOutcome {
    /// What the rule decided.
    pub decision: Decision,
    /// Whether the call goes on to the upstream server.
    pub forwarded: bool,
    /// The audit record, built before the taint update.
    pub audit: AuditEntry,
}

/// The taint state of one proxy session.
#[derive(Clone, Debug)]
pub struct SessionTaintState {
    level: TaintLevel,
    history: Vec<TaintEvent>,
    dropped_events: u64,
    sequence: u64,
}

impl Default for SessionTaintState {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionTaintState {
    /// A clean session with no history.
    pub fn new() -> Self {
        SessionTaintState {
            level: TaintLevel::Clean,
            history: Vec::new(),
            dropped_events: 0,
            sequence: 0,
        }
    }

    /// The current taint level.
    pub fn level(&self) -> TaintLevel {
        self.level
    }

    /// Whether the session is tainted.
    pub fn is_tainted(&self) -> bool {
        self.level == TaintLevel::Tainted
    }

    /// The retained taint events, oldest first, resets included.
    pub fn history(&self) -> &[TaintEvent] {
        &self.history
    }

    /// The `sequence:tool` entries since the last reset, capped at 16 plus a `+<n> more` tail.
    pub fn taint_chain(&self) -> Vec<String> {
        let since_reset = match self
            .history
            .iter()
            .rposition(|event| matches!(event, TaintEvent::Reset { .. }))
        {
            Some(reset_at) => &self.history[reset_at + 1..],
            None => &self.history[..],
        };
        let mut chain: Vec<String> = since_reset
            .iter()
            .filter_map(|event| match event {
                TaintEvent::Tainted(origin) => {
                    Some(format!("{}:{}", origin.sequence, origin.tool_name))
                }
                TaintEvent::Reset { .. } => None,
            })
            .collect();
        let hidden = chain.len().saturating_sub(MAX_CHAIN_ENTRIES) as u64 + self.dropped_events;
        chain.truncate(MAX_CHAIN_ENTRIES);
        if hidden > 0 {
            chain.push(format!("+{hidden} more"));
        }
        chain
    }

    /// The rule: sensitive arguments deny, and so does a tainted sink without an override.
    pub fn decide(&self, call: &AbstractCall) -> Decision {
        let unapproved_tainted_sink = call.category == SourceCategory::PrivilegedSink
            && self.is_tainted()
            && !call.override_allowed;
        if call.sensitivity == ArgSensitivity::Sensitive || unapproved_tainted_sink {
            Decision::Deny
        } else {
            Decision::Allow
        }
    }

    /// Evaluates one call, audits it, and records it when it is forwarded.
    pub fn step(&mut self, call: &AbstractCall) -> StepOutcome {
        self.sequence += 1;
        let sequence = self.sequence;
        let decision = self.decide(call);
        let audit = AuditEntry {
            sequence,
            tool_name: call.tool_name.clone(),
            category: call.category,
            sensitivity: call.sensitivity,
            taint_at_evaluation: self.level,
            decision,
        };
        let forwarded = decision == Decision::Allow;
        if forwarded {
            self.record_forwarded(sequence, &call.tool_name, call.category, None);
        }
        StepOutcome {
            decision,
            forwarded,
            audit,
        }
    }

    /// Taints the session for a forwarded untrusted source call; other categories change nothing.
    pub fn record_forwarded(
        &mut self,
        sequence: u64,
        tool_name: &str,
        category: SourceCategory,
        detail: Option<String>,
    ) {
        if category != SourceCategory::UntrustedSource {
            return;
        }
        self.level = TaintLevel::Tainted;
        self.push_event(TaintEvent::Tainted(TaintOrigin {
            sequence,
            tool_name: tool_name.to_string(),
            category,
            detail,
        }));
    }

    /// Returns a tainted session to `Clean` and logs it; does nothing when already clean.
    pub fn reset(&mut self) {
        if !self.is_tainted() {
            return;
        }
        self.level = TaintLevel::Clean;
        self.push_event(TaintEvent::Reset {
            sequence: self.sequence,
        });
        self.dropped_events = 0;
    }

    /// Appends an event, dropping the oldest one first when the history is full.
    fn push_event(&mut self, event: TaintEvent) {
        if self.history.len() == MAX_TAINT_HISTORY {
            let oldest = self.history.remove(0);
            let in_current_chain = matches!(oldest, TaintEvent::Tainted(_))
                && !self
                    .history
                    .iter()
                    .any(|kept| matches!(kept, TaintEvent::Reset { .. }));
            if in_current_chain {
                self.dropped_events += 1;
            }
        }
        self.history.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forwards one `fetch` source call per sequence number.
    fn forward_fetch_calls(
        state: &mut SessionTaintState,
        sequences: std::ops::RangeInclusive<u64>,
    ) {
        for sequence in sequences {
            state.record_forwarded(sequence, "fetch", SourceCategory::UntrustedSource, None);
        }
    }

    #[test]
    fn history_drops_oldest_event_at_cap() {
        let mut state = SessionTaintState::new();
        forward_fetch_calls(&mut state, 1..=4_100);
        let chain = state.taint_chain();
        assert!(state.is_tainted());
        assert_eq!(state.history().len(), 4_096);
        assert!(
            matches!(
                state.history().first(),
                Some(TaintEvent::Tainted(TaintOrigin { sequence: 5, .. }))
            ),
            "oldest retained event: {:?}",
            state.history().first()
        );
        assert_eq!(chain.len(), 17, "chain: {chain:?}");
        assert_eq!(chain[0], "5:fetch");
        assert_eq!(chain[15], "20:fetch");
        assert_eq!(chain[16], "+4084 more");
    }

    #[test]
    fn reset_is_a_no_op_when_clean() {
        let mut state = SessionTaintState::new();
        state.reset();
        assert_eq!(state.level(), TaintLevel::Clean);
        assert!(state.history().is_empty(), "history: {:?}", state.history());
    }
}
