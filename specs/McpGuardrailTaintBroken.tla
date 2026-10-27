------------------------ MODULE McpGuardrailTaintBroken ------------------------
(***************************************************************************)
(* A deliberately broken variant: ForwardEarly sends a PrivilegedSink call *)
(* to the child before the taint check runs. TLC must report               *)
(* NoUnapprovedTaintedSinkForwarded with a 7-action counterexample. This   *)
(* proves the invariant can fail, so the clean run of McpGuardrailTaint     *)
(* is evidence and not a vacuous pass.                                      *)
(***************************************************************************)
EXTENDS McpGuardrailTaint

\* The ordering bug: the decision never consults sessionTaint or
\* pendingCall.override. The audit entry is still appended, so
\* CompleteAuditTrail holds and cannot mask the target violation.
ForwardEarly ==
  /\ phase = "Received"
  /\ pendingCall.toolClass = "PrivilegedSink"
  /\ pendingCall.argSensitivity = "Safe"
  /\ decision' = "Allow"
  /\ auditLog' = Append(auditLog,
                        [seq            |-> callsCompleted + 1,
                         toolClass      |-> pendingCall.toolClass,
                         argSensitivity |-> pendingCall.argSensitivity,
                         taint          |-> sessionTaint,
                         decision       |-> "Allow"])
  /\ forwardedToChild' = TRUE
  /\ phase' = "Done"
  /\ UNCHANGED <<sessionTaint, taintHistory, pendingCall, callsCompleted>>

BrokenNext == Next \/ ForwardEarly

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
