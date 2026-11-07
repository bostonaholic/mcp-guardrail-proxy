----------------------------- MODULE CallJudgment -----------------------------
(***************************************************************************)
(* One evaluated call inside Interceptor::judge_call, at the grain of the  *)
(* code. McpGuardrailTaint proves the abstract rule; this spec adds the    *)
(* two branches it leaves out: the approval broker's three answers, and    *)
(* an audit sink that fails.                                                *)
(*                                                                          *)
(* The Policy* actions are the engine's verdict. Only the guard on          *)
(* PolicyAllow constrains it: engine_allow_implies_abstract_allow in        *)
(* src/policy.rs ties that guard to the engine.                             *)
(***************************************************************************)
VARIABLES phase,                 \* see Phases
          category,              \* "None" | "Benign" | "Source" | "Sink"
          decision,              \* "None" | "Allow" | "Deny" | "RequireApproval"
          forward,               \* the ruling lets the call through
          audit,                 \* "None" | "Durable" | "Fallback"
          taint,                 \* "Clean" | "Tainted"
          delivered              \* the child got this call

vars == <<phase, category, decision, forward, audit, taint, delivered>>

Phases == {"Idle", "Received", "AwaitingBroker", "Decided", "Forwarded", "Rejected",
           "Committed", "Done"}
Categories == {"Benign", "Source", "Sink"}

TypeOK ==
  /\ phase \in Phases
  /\ category \in Categories \cup {"None"}
  /\ decision \in {"None", "Allow", "Deny", "RequireApproval"}
  /\ forward \in BOOLEAN
  /\ audit \in {"None", "Durable", "Fallback"}
  /\ taint \in {"Clean", "Tainted"}
  /\ delivered \in BOOLEAN

Init ==
  /\ phase = "Idle"
  /\ category = "None"
  /\ decision = "None"
  /\ forward = FALSE
  /\ audit = "None"
  /\ taint = "Clean"
  /\ delivered = FALSE

Receive(c) ==
  /\ phase = "Idle"
  /\ phase' = "Received"
  /\ category' = c
  /\ UNCHANGED <<decision, forward, audit, taint, delivered>>

Rule(d, f, next) ==
  /\ decision' = d
  /\ forward' = f
  /\ phase' = next
  /\ UNCHANGED <<category, audit, taint, delivered>>

PolicyAllow ==
  /\ phase = "Received"
  /\ ~(category = "Sink" /\ taint = "Tainted")
  /\ Rule("Allow", TRUE, "Decided")

PolicyDeny ==
  /\ phase = "Received"
  /\ Rule("Deny", FALSE, "Decided")

PolicyRequireApproval ==
  /\ phase = "Received"
  /\ Rule("RequireApproval", FALSE, "AwaitingBroker")

BrokerApproved ==
  /\ phase = "AwaitingBroker"
  /\ Rule("RequireApproval", TRUE, "Decided")

BrokerDenied ==
  /\ phase = "AwaitingBroker"
  /\ Rule("Deny", FALSE, "Decided")

BrokerPending ==
  /\ phase = "AwaitingBroker"
  /\ Rule("RequireApproval", FALSE, "Decided")

\* The audit line is durable. Only now does the ruling take effect.
AuditRecorded ==
  /\ phase = "Decided"
  /\ audit' = "Durable"
  /\ phase' = IF forward THEN "Forwarded" ELSE "Rejected"
  /\ UNCHANGED <<category, decision, forward, taint, delivered>>

\* The sink failed. The call fails closed, and a fallback line goes to stderr.
AuditFailed ==
  /\ phase = "Decided"
  /\ audit' = "Fallback"
  /\ decision' = IF forward THEN "Deny" ELSE decision
  /\ forward' = FALSE
  /\ phase' = "Rejected"
  /\ UNCHANGED <<category, taint, delivered>>

\* Taint updates before the frame leaves, and the loop writes the frame before
\* it reads the next line. A failed write ends the session, so no later call
\* can see the difference.
RecordTaint ==
  /\ phase = "Forwarded"
  /\ taint' = IF category = "Source" THEN "Tainted" ELSE taint
  /\ phase' = "Committed"
  /\ UNCHANGED <<category, decision, forward, audit, delivered>>

Deliver ==
  /\ phase = "Committed"
  /\ delivered' = TRUE
  /\ phase' = "Done"
  /\ UNCHANGED <<category, decision, forward, audit, taint>>

Reply ==
  /\ phase = "Rejected"
  /\ phase' = "Done"
  /\ UNCHANGED <<category, decision, forward, audit, taint, delivered>>

Complete ==
  /\ phase = "Done"
  /\ phase' = "Idle"
  /\ category' = "None"
  /\ decision' = "None"
  /\ forward' = FALSE
  /\ audit' = "None"
  /\ delivered' = FALSE
  /\ UNCHANGED taint

Next ==
  \/ \E c \in Categories : Receive(c)
  \/ PolicyAllow
  \/ PolicyDeny
  \/ PolicyRequireApproval
  \/ BrokerApproved
  \/ BrokerDenied
  \/ BrokerPending
  \/ AuditRecorded
  \/ AuditFailed
  \/ RecordTaint
  \/ Deliver
  \/ Reply
  \/ Complete

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* The child sees a call only after its audit line is durable.
DeliveryFollowsDurableAudit == delivered => audit = "Durable"

\* A denied call never reaches the child.
DeniedNeverDelivered == decision = "Deny" => ~delivered

\* A call the broker left pending never reaches the child.
DeliveredWasRuledThrough == delivered => forward

\* In a tainted session, a sink reaches the child only through approval.
TaintedSinkNeedsApproval ==
  (delivered /\ category = "Sink" /\ taint = "Tainted") => decision = "RequireApproval"

\* A failed audit never lets a call through.
FallbackNeverForwards == audit = "Fallback" => (~forward /\ ~delivered)

\* Only a forwarded source with a durable audit line taints the session.
TaintOnlyFromForwardedSource ==
  [][taint' /= taint => (phase = "Forwarded" /\ category = "Source" /\ audit = "Durable")]_vars

\* Nothing in this machine clears taint.
TaintIsMonotonic == [][taint = "Tainted" => taint' = "Tainted"]_vars

=============================================================================
