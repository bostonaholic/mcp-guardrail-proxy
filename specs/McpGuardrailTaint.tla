--------------------------- MODULE McpGuardrailTaint ---------------------------
(***************************************************************************)
(* One proxy session that handles tool calls one at a time. Each call walks *)
(* Idle -> Received -> Evaluated -> Audited -> Done -> Idle. Forwarding an  *)
(* UntrustedSource call taints the session; a tainted session must not     *)
(* forward a PrivilegedSink call unless that call carries an override.     *)
(* The Rust mirror in tests/tla_trace_equivalence.rs explores the same     *)
(* state space.                                                             *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANT MaxCalls                \* McpGuardrailTaint.cfg: MaxCalls = 3

VARIABLES sessionTaint,          \* "Clean" | "Tainted"
          taintHistory,          \* Seq([kind: {"Tainted","Reset"}, seq: Nat])
          pendingCall,           \* Calls \cup {NoCall}
          decision,              \* "None" | "Allow" | "Deny" | "RequireApproval"
          forwardedToChild,      \* BOOLEAN, for the current call
          auditLog,              \* Seq([seq, toolClass, argSensitivity, taint, decision])
          phase,                 \* "Idle" | "Received" | "Evaluated" | "Audited" | "Done"
          callsCompleted         \* 0..MaxCalls

vars == <<sessionTaint, taintHistory, pendingCall, decision,
          forwardedToChild, auditLog, phase, callsCompleted>>

ToolClasses      == {"Benign", "UntrustedSource", "PrivilegedSink"}
ArgSensitivities == {"Safe", "Sensitive"}
TaintLevels      == {"Clean", "Tainted"}
Decisions        == {"None", "Allow", "Deny", "RequireApproval"}
Phases           == {"Idle", "Received", "Evaluated", "Audited", "Done"}

Calls  == [toolClass: ToolClasses, argSensitivity: ArgSensitivities, override: BOOLEAN]

\* Sentinel for "no call in flight". Its "None" field values keep it outside Calls.
NoCall == [toolClass |-> "None", argSensitivity |-> "None", override |-> FALSE]

Last(s) == s[Len(s)]

Decide(c, t) ==
  IF c.argSensitivity = "Sensitive" THEN "Deny"
  ELSE IF c.toolClass = "PrivilegedSink" /\ t = "Tainted" /\ ~c.override THEN "Deny"
  ELSE "Allow"

HistoryEntries == [kind: {"Tainted", "Reset"}, seq: 0..MaxCalls]
AuditEntries   == [seq: 1..MaxCalls, toolClass: ToolClasses,
                   argSensitivity: ArgSensitivities, taint: TaintLevels,
                   decision: Decisions]

\* Every variable holds a value of its declared shape.
TypeOK ==
  /\ sessionTaint \in TaintLevels
  /\ taintHistory \in Seq(HistoryEntries)
  /\ pendingCall \in Calls \cup {NoCall}
  /\ decision \in Decisions
  /\ forwardedToChild \in BOOLEAN
  /\ auditLog \in Seq(AuditEntries)
  /\ phase \in Phases
  /\ callsCompleted \in 0..MaxCalls

Init ==
  /\ sessionTaint = "Clean"
  /\ taintHistory = <<>>
  /\ pendingCall = NoCall
  /\ decision = "None"
  /\ forwardedToChild = FALSE
  /\ auditLog = <<>>
  /\ phase = "Idle"
  /\ callsCompleted = 0

\* The client sends call c.
Receive(c) ==
  /\ phase = "Idle"
  /\ callsCompleted < MaxCalls
  /\ pendingCall' = c
  /\ phase' = "Received"
  /\ UNCHANGED <<sessionTaint, taintHistory, decision, forwardedToChild,
                 auditLog, callsCompleted>>

\* The policy engine decides with the session taint as it is now.
Evaluate ==
  /\ phase = "Received"
  /\ decision' = Decide(pendingCall, sessionTaint)
  /\ phase' = "Evaluated"
  /\ UNCHANGED <<sessionTaint, taintHistory, pendingCall, forwardedToChild,
                 auditLog, callsCompleted>>

\* The decision is written to the audit log before any effect.
Audit ==
  /\ phase = "Evaluated"
  /\ auditLog' = Append(auditLog,
                        [seq            |-> callsCompleted + 1,
                         toolClass      |-> pendingCall.toolClass,
                         argSensitivity |-> pendingCall.argSensitivity,
                         taint          |-> sessionTaint,
                         decision       |-> decision])
  /\ phase' = "Audited"
  /\ UNCHANGED <<sessionTaint, taintHistory, pendingCall, decision,
                 forwardedToChild, callsCompleted>>

\* An allowed call goes to the child server. An UntrustedSource call taints.
Forward ==
  /\ phase = "Audited"
  /\ decision = "Allow"
  /\ forwardedToChild' = TRUE
  /\ IF pendingCall.toolClass = "UntrustedSource"
       THEN /\ sessionTaint' = "Tainted"
            /\ taintHistory' = Append(taintHistory,
                                      [kind |-> "Tainted", seq |-> callsCompleted + 1])
       ELSE UNCHANGED <<sessionTaint, taintHistory>>
  /\ phase' = "Done"
  /\ UNCHANGED <<pendingCall, decision, auditLog, callsCompleted>>

\* A denied call gets an error response and never reaches the child.
Reject ==
  /\ phase = "Audited"
  /\ decision \in {"Deny", "RequireApproval"}
  /\ phase' = "Done"
  /\ UNCHANGED <<sessionTaint, taintHistory, pendingCall, decision,
                 forwardedToChild, auditLog, callsCompleted>>

\* The call is finished; the per-call variables return to their idle values.
Complete ==
  /\ phase = "Done"
  /\ callsCompleted' = callsCompleted + 1
  /\ pendingCall' = NoCall
  /\ decision' = "None"
  /\ forwardedToChild' = FALSE
  /\ phase' = "Idle"
  /\ UNCHANGED <<sessionTaint, taintHistory, auditLog>>

\* An operator clears the taint between calls; the history records it.
Reset ==
  /\ phase = "Idle"
  /\ sessionTaint = "Tainted"
  /\ sessionTaint' = "Clean"
  /\ taintHistory' = Append(taintHistory, [kind |-> "Reset", seq |-> callsCompleted])
  /\ UNCHANGED <<pendingCall, decision, forwardedToChild, auditLog, phase,
                 callsCompleted>>

Next ==
  \/ \E c \in Calls : Receive(c)
  \/ Evaluate
  \/ Audit
  \/ Forward
  \/ Reject
  \/ Complete
  \/ Reset

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* A PrivilegedSink call reaches the child while the session is tainted only
\* when that call carries an explicit override.
NoUnapprovedTaintedSinkForwarded ==
  (forwardedToChild /\ pendingCall.toolClass = "PrivilegedSink" /\ sessionTaint = "Tainted")
    => pendingCall.override

\* A call with sensitive arguments never reaches the child.
SensitiveArgsNeverForwarded ==
  forwardedToChild => pendingCall.argSensitivity = "Safe"

\* A clean session has never been tainted, or its latest history event is a
\* Reset: taint only goes away through an explicit, recorded Reset.
MonotonicSessionTaint ==
  sessionTaint = "Clean" => (taintHistory = <<>> \/ Last(taintHistory).kind = "Reset")

\* Action form of the above (a PROPERTY): every step from Tainted to Clean
\* appends exactly one history event, and that event is a Reset.
MonotonicTaintStep ==
  [][(sessionTaint = "Tainted" /\ sessionTaint' = "Clean")
       => (/\ Last(taintHistory').kind = "Reset"
           /\ Len(taintHistory') = Len(taintHistory) + 1)]_vars

\* Every call that got past Evaluate has exactly one audit entry, the latest
\* entry records the current decision, and forwarding happens only after audit.
CompleteAuditTrail ==
  /\ Len(auditLog) = callsCompleted + (IF phase \in {"Audited", "Done"} THEN 1 ELSE 0)
  /\ phase \in {"Audited", "Done"} => Last(auditLog).decision = decision
  /\ forwardedToChild => phase = "Done"

=============================================================================
