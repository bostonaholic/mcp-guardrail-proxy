---------------------- MODULE DashboardWatchUnreadBroken ----------------------
(***************************************************************************)
(* A deliberately broken variant: the history read trusts a saved read     *)
(* mark that names a blocked call the log does not hold. Such a mark was   *)
(* saved for a log that has since been replaced. Kept, it hides the new    *)
(* log's blocked calls that take those places. TLC must report             *)
(* MarkFitsTheLog.                                                         *)
(***************************************************************************)
EXTENDS DashboardWatch

StaleMarkKept(count) ==
  /\ phase = "LoadingHistory"
  /\ revision < MaxRevision
  /\ count >= blocked
  /\ ~(savedRead \subseteq 1..count)
  /\ Settle("None", revision + 1, count, savedRead)
  /\ MayAlertIfLive
  /\ markedRead' = {}
  /\ phase' = "Live"

BrokenSpec ==
  Init /\ [][Next \/ \E count \in 0..MaxBlocked : StaleMarkKept(count)]_vars

=============================================================================
