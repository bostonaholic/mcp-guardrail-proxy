-------------------------- MODULE CallJudgmentBroken --------------------------
(***************************************************************************)
(* A deliberately broken variant: a failed audit sink fails open, and the  *)
(* call goes through anyway. TLC must report FallbackNeverForwards.         *)
(***************************************************************************)
EXTENDS CallJudgment

AuditFailsOpen ==
  /\ phase = "Decided"
  /\ forward
  /\ audit' = "Fallback"
  /\ phase' = "Forwarded"
  /\ UNCHANGED <<category, decision, forward, taint, delivered>>

BrokenSpec == Init /\ [][Next \/ AuditFailsOpen]_vars

=============================================================================
