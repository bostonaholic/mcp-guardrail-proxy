//! Trace-equivalence tests for `specs/McpGuardrailTaint.tla`.
//!
//! Part 1 (std only) is an explicit-state mirror of the TLA+ spec. `SpecModel`
//! has one Rust value per TLA+ variable and one function per TLA+ action. A
//! breadth-first explorer checks the spec's invariants on every reachable
//! state, so `scripts/verify-tla.sh` can still give a verdict on a machine
//! without TLC or Java.

use std::collections::{HashSet, VecDeque};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum ToolClass {
    Benign,
    UntrustedSource,
    PrivilegedSink,
}

const TOOL_CLASSES: [ToolClass; 3] = [
    ToolClass::Benign,
    ToolClass::UntrustedSource,
    ToolClass::PrivilegedSink,
];

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum ArgSens {
    Safe,
    Sensitive,
}

const ARG_SENSITIVITIES: [ArgSens; 2] = [ArgSens::Safe, ArgSens::Sensitive];

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Phase {
    Idle,
    Received,
    Evaluated,
    Audited,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum TaintLevel {
    Clean,
    Tainted,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Decision {
    None,
    Allow,
    Deny,
    // `Decide` never returns it; the spec keeps it so `Reject` covers the
    // approval path that the crate adds.
    #[allow(dead_code, reason = "mirrors the TLA+ Decisions set")]
    RequireApproval,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum HistoryKind {
    Tainted,
    Reset,
}

/// A member of the TLA+ set `Calls`. `NoCall` is `Option::None`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Call {
    tool_class: ToolClass,
    arg_sens: ArgSens,
    override_allowed: bool,
}

/// `[kind, seq]`, one element of `taintHistory`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct HistoryEntry {
    kind: HistoryKind,
    seq: u32,
}

/// `[seq, toolClass, argSensitivity, taint, decision]`, one element of `auditLog`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct AuditEntry {
    seq: u32,
    tool_class: ToolClass,
    arg_sens: ArgSens,
    taint: TaintLevel,
    decision: Decision,
}

/// One TLA+ state: a field per variable, in declaration order.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct SpecState {
    session_taint: TaintLevel,
    taint_history: Vec<HistoryEntry>,
    pending_call: Option<Call>,
    decision: Decision,
    forwarded_to_child: bool,
    audit_log: Vec<AuditEntry>,
    phase: Phase,
    calls_completed: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    Receive(Call),
    Evaluate,
    Audit,
    Forward,
    Reject,
    Complete,
    Reset,
    ForwardEarly,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Receive(call) => write!(
                f,
                "Receive({:?}, {:?}, override={})",
                call.tool_class, call.arg_sens, call.override_allowed
            ),
            other => write!(f, "{other:?}"),
        }
    }
}

/// `Calls`: every tool class x argument sensitivity x override (12 calls).
fn all_calls() -> Vec<Call> {
    let mut calls = Vec::with_capacity(12);
    for tool_class in TOOL_CLASSES {
        for arg_sens in ARG_SENSITIVITIES {
            for override_allowed in [false, true] {
                calls.push(Call {
                    tool_class,
                    arg_sens,
                    override_allowed,
                });
            }
        }
    }
    calls
}

/// `Decide(c, t)`: sensitive arguments, or a tainted sink without override, deny.
fn decide(call: Call, taint: TaintLevel) -> Decision {
    let sensitive = call.arg_sens == ArgSens::Sensitive;
    let unapproved_tainted_sink = call.tool_class == ToolClass::PrivilegedSink
        && taint == TaintLevel::Tainted
        && !call.override_allowed;
    if sensitive || unapproved_tainted_sink {
        Decision::Deny
    } else {
        Decision::Allow
    }
}

/// Every phase after `Idle` has a call in flight; a missing one is a model bug.
fn pending(s: &SpecState) -> Call {
    s.pending_call
        .expect("phase after Idle must have a pending call")
}

fn audit_entry(s: &SpecState, decision: Decision) -> AuditEntry {
    let call = pending(s);
    AuditEntry {
        seq: s.calls_completed + 1,
        tool_class: call.tool_class,
        arg_sens: call.arg_sens,
        taint: s.session_taint,
        decision,
    }
}

// One function per TLA+ action: `None` when the action is disabled in `s`,
// otherwise the successor state.

fn receive(s: &SpecState, call: Call, max_calls: u32) -> Option<SpecState> {
    (s.phase == Phase::Idle && s.calls_completed < max_calls).then(|| SpecState {
        pending_call: Some(call),
        phase: Phase::Received,
        ..s.clone()
    })
}

fn evaluate(s: &SpecState) -> Option<SpecState> {
    (s.phase == Phase::Received).then(|| SpecState {
        decision: decide(pending(s), s.session_taint),
        phase: Phase::Evaluated,
        ..s.clone()
    })
}

fn audit(s: &SpecState) -> Option<SpecState> {
    (s.phase == Phase::Evaluated).then(|| {
        let mut audit_log = s.audit_log.clone();
        audit_log.push(audit_entry(s, s.decision));
        SpecState {
            audit_log,
            phase: Phase::Audited,
            ..s.clone()
        }
    })
}

fn forward(s: &SpecState) -> Option<SpecState> {
    (s.phase == Phase::Audited && s.decision == Decision::Allow).then(|| {
        let mut next = SpecState {
            forwarded_to_child: true,
            phase: Phase::Done,
            ..s.clone()
        };
        if pending(s).tool_class == ToolClass::UntrustedSource {
            next.session_taint = TaintLevel::Tainted;
            next.taint_history.push(HistoryEntry {
                kind: HistoryKind::Tainted,
                seq: s.calls_completed + 1,
            });
        }
        next
    })
}

fn reject(s: &SpecState) -> Option<SpecState> {
    let denied = matches!(s.decision, Decision::Deny | Decision::RequireApproval);
    (s.phase == Phase::Audited && denied).then(|| SpecState {
        phase: Phase::Done,
        ..s.clone()
    })
}

fn complete(s: &SpecState) -> Option<SpecState> {
    (s.phase == Phase::Done).then(|| SpecState {
        calls_completed: s.calls_completed + 1,
        pending_call: None,
        decision: Decision::None,
        forwarded_to_child: false,
        phase: Phase::Idle,
        ..s.clone()
    })
}

fn reset(s: &SpecState) -> Option<SpecState> {
    (s.phase == Phase::Idle && s.session_taint == TaintLevel::Tainted).then(|| {
        let mut taint_history = s.taint_history.clone();
        taint_history.push(HistoryEntry {
            kind: HistoryKind::Reset,
            seq: s.calls_completed,
        });
        SpecState {
            session_taint: TaintLevel::Clean,
            taint_history,
            ..s.clone()
        }
    })
}

/// `McpGuardrailTaintBroken!ForwardEarly`: forwards a safe sink call before
/// the taint check. It never consults `session_taint` or `override_allowed`.
fn forward_early(s: &SpecState) -> Option<SpecState> {
    let enabled = s.phase == Phase::Received
        && s.pending_call.is_some_and(|c| {
            c.tool_class == ToolClass::PrivilegedSink && c.arg_sens == ArgSens::Safe
        });
    enabled.then(|| {
        let mut audit_log = s.audit_log.clone();
        audit_log.push(audit_entry(s, Decision::Allow));
        SpecState {
            decision: Decision::Allow,
            audit_log,
            forwarded_to_child: true,
            phase: Phase::Done,
            ..s.clone()
        }
    })
}

/// `Spec` (or `BrokenSpec` when `broken`) with the constant `MaxCalls`.
struct SpecModel {
    max_calls: u32,
    broken: bool,
}

impl SpecModel {
    /// `Init`.
    fn init() -> SpecState {
        SpecState {
            session_taint: TaintLevel::Clean,
            taint_history: Vec::new(),
            pending_call: None,
            decision: Decision::None,
            forwarded_to_child: false,
            audit_log: Vec::new(),
            phase: Phase::Idle,
            calls_completed: 0,
        }
    }

    /// `Next` (or `BrokenNext`): every enabled action with its successor.
    fn next(&self, s: &SpecState) -> Vec<(Action, SpecState)> {
        let mut successors: Vec<(Action, SpecState)> = all_calls()
            .into_iter()
            .filter_map(|call| receive(s, call, self.max_calls).map(|t| (Action::Receive(call), t)))
            .collect();
        let mut others = vec![
            (Action::Evaluate, evaluate(s)),
            (Action::Audit, audit(s)),
            (Action::Forward, forward(s)),
            (Action::Reject, reject(s)),
            (Action::Complete, complete(s)),
            (Action::Reset, reset(s)),
        ];
        if self.broken {
            others.push((Action::ForwardEarly, forward_early(s)));
        }
        successors.extend(
            others
                .into_iter()
                .filter_map(|(action, t)| t.map(|t| (action, t))),
        );
        successors
    }
}

fn implies(premise: bool, conclusion: bool) -> bool {
    !premise || conclusion
}

/// A PrivilegedSink call reaches the child while the session is tainted only
/// when that call carries an explicit override.
fn no_unapproved_tainted_sink_forwarded(s: &SpecState) -> bool {
    let tainted_sink_forwarded = s.forwarded_to_child
        && s.pending_call
            .is_some_and(|c| c.tool_class == ToolClass::PrivilegedSink)
        && s.session_taint == TaintLevel::Tainted;
    implies(
        tainted_sink_forwarded,
        s.pending_call.is_some_and(|c| c.override_allowed),
    )
}

/// A call with sensitive arguments never reaches the child.
fn sensitive_args_never_forwarded(s: &SpecState) -> bool {
    implies(
        s.forwarded_to_child,
        s.pending_call.is_some_and(|c| c.arg_sens == ArgSens::Safe),
    )
}

/// A clean session was never tainted, or its latest history event is a Reset.
fn monotonic_session_taint(s: &SpecState) -> bool {
    implies(
        s.session_taint == TaintLevel::Clean,
        matches!(
            s.taint_history.last(),
            None | Some(HistoryEntry {
                kind: HistoryKind::Reset,
                ..
            })
        ),
    )
}

/// Every call past Evaluate has one audit entry, the latest entry holds the
/// current decision, and forwarding happens only after the audit.
fn complete_audit_trail(s: &SpecState) -> bool {
    let in_flight = matches!(s.phase, Phase::Audited | Phase::Done);
    let expected_len = s.calls_completed + u32::from(in_flight);
    s.audit_log.len() == expected_len as usize
        && implies(
            in_flight,
            s.audit_log.last().is_some_and(|e| e.decision == s.decision),
        )
        && implies(s.forwarded_to_child, s.phase == Phase::Done)
}

/// `MonotonicTaintStep` (action form): a step from Tainted to Clean appends
/// exactly one history event, and it is a Reset.
fn monotonic_taint_step(prev: &SpecState, next: &SpecState) -> bool {
    let cleaned =
        prev.session_taint == TaintLevel::Tainted && next.session_taint == TaintLevel::Clean;
    implies(
        cleaned,
        matches!(
            next.taint_history.last(),
            Some(HistoryEntry {
                kind: HistoryKind::Reset,
                ..
            })
        ) && next.taint_history.len() == prev.taint_history.len() + 1,
    )
}

type StateInvariant = (&'static str, fn(&SpecState) -> bool);

/// The cfg's INVARIANTS after TypeOK, in cfg order. The Rust types enforce TypeOK.
const INVARIANTS: [StateInvariant; 4] = [
    (
        "NoUnapprovedTaintedSinkForwarded",
        no_unapproved_tainted_sink_forwarded,
    ),
    (
        "SensitiveArgsNeverForwarded",
        sensitive_args_never_forwarded,
    ),
    ("MonotonicSessionTaint", monotonic_session_taint),
    ("CompleteAuditTrail", complete_audit_trail),
];

#[derive(Debug)]
struct Violation {
    invariant: &'static str,
    /// The actions from `Init` to the violating state, each with its successor.
    trace: Vec<(Action, SpecState)>,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} violated after {} actions:",
            self.invariant,
            self.trace.len()
        )?;
        writeln!(f, "  0: Init -> {:?}", SpecModel::init())?;
        for (step, (action, state)) in self.trace.iter().enumerate() {
            writeln!(f, "  {}: {action} -> {state:?}", step + 1)?;
        }
        Ok(())
    }
}

fn first_broken_invariant(s: &SpecState) -> Option<&'static str> {
    INVARIANTS
        .iter()
        .find(|(_, holds)| !holds(s))
        .map(|(name, _)| *name)
}

/// The actions from `Init` to `states[i]`, following parent links.
fn trace_to(
    states: &[SpecState],
    parents: &[Option<(usize, Action)>],
    mut i: usize,
) -> Vec<(Action, SpecState)> {
    let mut trace = Vec::new();
    while let Some((parent, action)) = parents[i] {
        trace.push((action, states[i].clone()));
        i = parent;
    }
    trace.reverse();
    trace
}

/// Breadth-first search over every reachable state. Returns the number of
/// distinct states, or the shortest trace to the first violation found.
fn explore(model: &SpecModel) -> Result<usize, Violation> {
    let init = SpecModel::init();
    // `states[i]` was reached from `parents[i]`. BFS order makes every trace shortest.
    let mut states = vec![init.clone()];
    let mut parents: Vec<Option<(usize, Action)>> = vec![None];
    let mut seen = HashSet::from([init]);
    let mut queue = VecDeque::from([0]);

    if let Some(invariant) = first_broken_invariant(&states[0]) {
        return Err(Violation {
            invariant,
            trace: Vec::new(),
        });
    }

    while let Some(i) = queue.pop_front() {
        for (action, next) in model.next(&states[i]) {
            if !monotonic_taint_step(&states[i], &next) {
                let mut trace = trace_to(&states, &parents, i);
                trace.push((action, next));
                return Err(Violation {
                    invariant: "MonotonicTaintStep",
                    trace,
                });
            }
            if seen.contains(&next) {
                continue;
            }
            seen.insert(next.clone());
            let j = states.len();
            states.push(next);
            parents.push(Some((i, action)));
            if let Some(invariant) = first_broken_invariant(&states[j]) {
                return Err(Violation {
                    invariant,
                    trace: trace_to(&states, &parents, j),
                });
            }
            queue.push_back(j);
        }
    }
    Ok(states.len())
}

#[test]
fn spec_model_satisfies_all_invariants() {
    let model = SpecModel {
        max_calls: 3,
        broken: false,
    };
    let distinct = explore(&model).unwrap_or_else(|violation| panic!("{violation}"));
    println!("McpGuardrailTaint (MaxCalls = 3): {distinct} distinct states, no violation");
}

#[test]
fn broken_spec_model_violates_no_unapproved_tainted_sink_forwarded() {
    let model = SpecModel {
        max_calls: 3,
        broken: true,
    };
    let violation = explore(&model).expect_err("BrokenSpec must violate an invariant");
    println!("McpGuardrailTaintBroken: {violation}");
    assert_eq!(violation.invariant, "NoUnapprovedTaintedSinkForwarded");
    assert_eq!(violation.trace.len(), 7);
    assert!(matches!(
        violation.trace.last(),
        Some((Action::ForwardEarly, _))
    ));
}

// Part 2 (crate-dependent equivalence tests) lands in commit 3.
