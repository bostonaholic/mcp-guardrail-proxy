---------------------- MODULE DashboardWatchUnreadBroken ----------------------
(***************************************************************************)
(* A deliberately broken variant: the history read trusts a saved read     *)
(* mark that is above the log's blocked calls. Such a mark was saved for   *)
(* a log that has since been replaced. Kept, it hides the new log's next   *)
(* blocked calls until their count passes it. TLC must report              *)
(* MarkFitsTheLog.                                                         *)
(***************************************************************************)
EXTENDS DashboardWatch

StaleMarkKept(count) ==
  /\ phase = "LoadingHistory"
  /\ revision < MaxRevision
  /\ count >= blocked
  /\ count < savedCount
  /\ Settle("None", revision + 1, count, savedCount)
  /\ MayAlertIfLive
  /\ markedRead' = 0
  /\ phase' = "Live"

BrokenSpec ==
  Init /\ [][Next \/ \E count \in 0..MaxBlocked : StaleMarkKept(count)]_vars

=============================================================================
