---------------------- MODULE DashboardWatchHistoryBroken ----------------------
(***************************************************************************)
(* A deliberately broken variant, and the behavior before the machine was  *)
(* explicit: when the launch read fails, the first read that works counts  *)
(* as live, so history raises a notification. TLC must report              *)
(* HistoryStaysSilent.                                                      *)
(***************************************************************************)
EXTENDS DashboardWatch

HistoryCountsAsLive ==
  /\ phase = "LoadingHistory"
  /\ error /= "None"
  /\ revision < MaxRevision
  /\ Settle("None", revision + 1)
  /\ mayAlert' = TRUE
  /\ alertedOnHistory' = TRUE
  /\ phase' = "Live"

BrokenSpec == Init /\ [][Next \/ HistoryCountsAsLive]_vars

=============================================================================
